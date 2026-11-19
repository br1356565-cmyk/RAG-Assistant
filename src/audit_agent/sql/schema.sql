-- DevOps Audit Agent schema (PostgreSQL 15+; RDS t3.small is enough).
--
-- Team isolation is enforced HERE, not in application code or prompts:
--   * every request runs in a transaction that sets app.team_ids / app.role / app.user_id
--     with set_config(..., is_local => true), so the values vanish at commit/rollback;
--   * row-level security policies read those settings;
--   * if nothing is set, every policy matches zero rows (fail closed).
--
-- Roles
--   (master)      owns the tables; used only by the migrate Lambda
--   audit_ingest  weekly ingest Lambda: writes findings, owners, runs, aggregates.
--                 Gets explicit allow-all policies rather than BYPASSRLS, which the RDS
--                 master user may not be allowed to grant.
--   audit_app     chat + investigation Lambdas: reads under RLS, writes only what policies allow
-- The migrate Lambda creates LOGIN users in these roles and grants rds_iam to them.
-- Idempotent: safe to run on every deploy. (gen_random_uuid() is core since PostgreSQL 13.)

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'audit_app')    then create role audit_app nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'audit_ingest') then create role audit_ingest nologin; end if;
end $$;

-- Helpers: read request scope. NULL / '' settings yield an empty array -> no rows.
create or replace function app_team_ids() returns text[] language sql stable as $$
  select coalesce(string_to_array(nullif(current_setting('app.team_ids', true), ''), ','), '{}'::text[])
$$;
create or replace function app_role() returns text language sql stable as $$
  select coalesce(nullif(current_setting('app.role', true), ''), 'none')
$$;
create or replace function app_user_id() returns text language sql stable as $$
  select nullif(current_setting('app.user_id', true), '')
$$;
create or replace function app_is_admin() returns boolean language sql stable as $$
  select app_role() = 'security_admin'
$$;

-- ── Reference data ─────────────────────────────────────────────────────────
create table if not exists teams (
  id              text primary key,             -- matches reports.yml team keys, e.g. growth_engineering
  name            text not null,
  entra_group_id  text unique                   -- Entra security group whose members belong to this team
);

create table if not exists repo_owners (
  repo        text primary key,                 -- repo name within the org
  team_id     text references teams(id),        -- null = unowned
  source      text not null,                    -- admin_team | override | codeowners | approved_proposal
  confidence  text not null default 'confirmed',-- confirmed | likely | unknown
  approved_by text,
  updated_at  timestamptz not null default now()
);

-- ── Findings ───────────────────────────────────────────────────────────────
create table if not exists findings (
  fingerprint  text primary key check (fingerprint ~ '^[0-9a-f]{16}$'),
  team_id      text references teams(id),       -- null = unowned (visible to admins only)
  source       text not null,                   -- dependabot | guardduty | security_hub | readme | ...
  resource     text not null,                   -- repo name, AWS account/resource, or username
  rule         text not null,                   -- advisory id, finding type, control id, policy name
  title        text not null,
  severity     text not null check (severity in ('critical','high','medium','low','info')),
  status       text not null default 'open' check (status in ('open','fixed','suppressed')),
  data_class   text not null default 'team' check (data_class in ('team','admin_only')),
  details      jsonb not null default '{}',     -- source-specific fields; never secret values
  first_seen   timestamptz not null,
  last_seen    timestamptz not null
);
create index if not exists findings_team_status on findings (team_id, status, severity);
create index if not exists findings_resource on findings (resource);

create table if not exists finding_events (
  id           bigserial primary key,
  fingerprint  text not null references findings(fingerprint) on delete cascade,
  team_id      text,
  event        text not null check (event in ('opened','seen','fixed','reopened','suppressed')),
  at           timestamptz not null default now()
);
create index if not exists finding_events_fp on finding_events (fingerprint, at);

create table if not exists weekly_aggregates (
  team_id  text not null references teams(id),
  week     date not null,                       -- Monday of the ISO week
  counts   jsonb not null,                      -- {"open":{"critical":3,...},"opened":4,"fixed":9}
  primary key (team_id, week)
);

create table if not exists runs (
  run_id      text primary key,
  started_at  timestamptz not null default now(),
  finished_at timestamptz,
  status      text not null default 'running'
);
create table if not exists run_collectors (
  run_id     text not null references runs(run_id) on delete cascade,
  collector  text not null,
  status     text not null,                     -- succeeded | failed
  duration_s numeric,
  error      text,
  primary key (run_id, collector)
);

-- ── Memory ─────────────────────────────────────────────────────────────────
-- Investigation memory: one explanation per finding per evidence state.
create table if not exists investigations (
  id             bigserial primary key,
  fingerprint    text not null references findings(fingerprint) on delete cascade,
  team_id        text not null references teams(id),
  evidence_hash  text not null,
  prompt_version text not null,
  model          text not null,
  explanation    jsonb not null,
  created_at     timestamptz not null default now()
);
-- v2: a rejected or disputed investigation is redone with the same evidence, so the old
-- uniqueness rule goes; low-confidence results wait for a person (needs_review).
alter table investigations drop constraint if exists investigations_fingerprint_evidence_hash_prompt_version_key;
alter table investigations add column if not exists needs_review boolean not null default false;
alter table investigations add column if not exists run_id text;
alter table investigations add column if not exists confidence real;
create index if not exists investigations_latest on investigations (fingerprint, created_at desc);

-- Human decisions on investigations. Append-only: the latest row is the current state.
create table if not exists investigation_reviews (
  id               bigserial primary key,
  investigation_id bigint not null references investigations(id) on delete cascade,
  team_id          text not null references teams(id),
  decision         text not null check (decision in ('approved','rejected','disputed')),
  reviewer         text not null,
  note             text check (length(note) <= 1000),
  fix_override     text check (length(fix_override) <= 300),
  created_at       timestamptz not null default now()
);
create index if not exists reviews_by_investigation on investigation_reviews (investigation_id, created_at desc);

-- auto: confident, no review needed · pending: low confidence, waiting for a lead
-- approved / rejected: decided by a lead · disputed: a team member says it is wrong
create or replace function review_state(inv_id bigint, inv_needs_review boolean) returns text
language sql stable as $$
  select coalesce(
    (select decision from investigation_reviews r where r.investigation_id = inv_id
      order by r.created_at desc, r.id desc limit 1),
    case when inv_needs_review then 'pending' else 'auto' end)
$$;

-- One waiting Step Functions task per weekly run that has items to review.
create table if not exists review_gates (
  run_id      text primary key,
  task_token  text not null,
  pending     int  not null,
  created_at  timestamptz not null default now(),
  resolved_at timestamptz
);

-- Thumbs up/down on chat answers.
create table if not exists answer_feedback (
  id          bigserial primary key,
  user_id     text not null,
  session_id  text not null,
  job_id      uuid,
  rating      smallint not null check (rating in (-1, 1)),
  comment     text check (length(comment) <= 1000),
  answer      text check (length(answer) <= 4000),
  created_at  timestamptz not null default now()
);

-- Fix requests drafted by the fix agent. Nothing reaches GitHub unless status = 'approved'.
create table if not exists fix_requests (
  id            uuid primary key,
  fingerprint   text not null references findings(fingerprint) on delete cascade,
  team_id       text not null references teams(id),
  repo          text not null,
  status        text not null default 'drafting'
                check (status in ('drafting','awaiting_approval','approved','rejected','opened','failed')),
  requested_by  text not null,
  manifest_path text,
  diff          text,
  new_content   text,
  rationale     text,
  thread_id     text not null,
  approver      text,
  decided_at    timestamptz,
  approved_sha256 text,                  -- hash of new_content at approval; the PR must match it
  pr_url        text,
  error         text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
-- One fix per package: a request covers every open finding for that package in that manifest.
alter table fix_requests add column if not exists package text;
alter table fix_requests add column if not exists covers text[] not null default '{}';
alter table fix_requests add column if not exists major_upgrade boolean not null default false;
create index if not exists fix_requests_fp on fix_requests (fingerprint, created_at desc);
create index if not exists fix_requests_covers on fix_requests using gin (covers);

-- Team knowledge: accepted risks, false positives, context. Agent may only PROPOSE.
create table if not exists team_notes (
  id           uuid primary key default gen_random_uuid(),
  team_id      text not null references teams(id),
  kind         text not null check (kind in ('accepted_risk','false_positive','context')),
  fingerprint  text references findings(fingerprint) on delete set null,
  text         text not null check (length(text) <= 1000),
  status       text not null default 'proposed' check (status in ('proposed','active','rejected')),
  author       text not null,                   -- user id, or 'agent:<user id>' for agent proposals
  approver     text,
  expires_at   date,
  created_at   timestamptz not null default now(),
  check (kind <> 'accepted_risk' or expires_at is not null)
);
alter table team_notes add column if not exists decided_at timestamptz;

-- Session memory (short-term). Cleanup job deletes expired rows daily.
create table if not exists session_turns (
  user_id     text not null,
  session_id  text not null,
  turn        int  not null,
  role        text not null check (role in ('user','assistant')),
  content     text not null,
  cited       text[] not null default '{}',
  expires_at  timestamptz not null default now() + interval '7 days',
  primary key (user_id, session_id, turn)
);

-- Chat requests run as background jobs so the page can show progress ("Checking GitHub
-- advisory ..."). Each row belongs to one user; rows older than 2 days are deleted weekly.
create table if not exists chat_jobs (
  id          uuid primary key,
  user_id     text not null,
  session_id  text not null,
  status      text not null default 'running' check (status in ('running','done','error')),
  steps       jsonb not null default '[]',
  result      jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists user_prefs (
  user_id  text primary key,
  prefs    jsonb not null default '{}'
);

create table if not exists audit_log (
  id          bigserial primary key,
  at          timestamptz not null default now(),
  user_id     text not null,
  team_ids    text[] not null,
  mode        text not null,                    -- chat | investigate
  question    text,
  tools       jsonb not null default '[]',      -- [{"name":..., "ok":..., "ms":...}]
  finding_ids text[] not null default '{}',     -- every finding returned to the model
  model       text,
  tokens      int
);

-- ── Row-level security ─────────────────────────────────────────────────────
alter table findings          enable row level security;  alter table findings          force row level security;
alter table finding_events    enable row level security;  alter table finding_events    force row level security;
alter table weekly_aggregates enable row level security;  alter table weekly_aggregates force row level security;
alter table investigations    enable row level security;  alter table investigations    force row level security;
alter table team_notes        enable row level security;  alter table team_notes        force row level security;
alter table session_turns     enable row level security;  alter table session_turns     force row level security;
alter table user_prefs        enable row level security;  alter table user_prefs        force row level security;
alter table chat_jobs         enable row level security;  alter table chat_jobs         force row level security;
alter table investigation_reviews enable row level security; alter table investigation_reviews force row level security;
alter table answer_feedback   enable row level security;  alter table answer_feedback   force row level security;
alter table fix_requests      enable row level security;  alter table fix_requests      force row level security;
alter table audit_log         enable row level security;  alter table audit_log         force row level security;

drop policy if exists findings_read on findings;
create policy findings_read on findings for select to audit_app using (
  app_is_admin()
  or (team_id = any (app_team_ids()) and data_class = 'team')
);

drop policy if exists events_read on finding_events;
create policy events_read on finding_events for select to audit_app using (
  app_is_admin() or team_id = any (app_team_ids())
);

drop policy if exists aggregates_read on weekly_aggregates;
create policy aggregates_read on weekly_aggregates for select to audit_app using (
  app_is_admin() or team_id = any (app_team_ids())
);

drop policy if exists investigations_read on investigations;
create policy investigations_read on investigations for select to audit_app using (
  app_is_admin() or team_id = any (app_team_ids())
);
drop policy if exists investigations_write on investigations;
create policy investigations_write on investigations for insert to audit_app with check (
  team_id = any (app_team_ids())
);

drop policy if exists notes_read on team_notes;
create policy notes_read on team_notes for select to audit_app using (
  app_is_admin() or team_id = any (app_team_ids())
);
-- The app may only insert PROPOSALS for a team in scope. Activation happens in the approval UI path.
drop policy if exists notes_propose on team_notes;
create policy notes_propose on team_notes for insert to audit_app with check (
  team_id = any (app_team_ids()) and status = 'proposed' and approver is null
);

drop policy if exists sessions_own on session_turns;
create policy sessions_own on session_turns for all to audit_app
  using (user_id = app_user_id()) with check (user_id = app_user_id());

drop policy if exists prefs_own on user_prefs;
create policy prefs_own on user_prefs for all to audit_app
  using (user_id = app_user_id()) with check (user_id = app_user_id());

-- Leads (and admins) decide proposed notes for their own teams, as themselves.
drop policy if exists notes_decide on team_notes;
create policy notes_decide on team_notes for update to audit_app
  using (status = 'proposed' and (app_is_admin() or (team_id = any (app_team_ids()) and app_role() = 'team_lead')))
  with check (status in ('active','rejected') and approver = app_user_id()
              and (app_is_admin() or (team_id = any (app_team_ids()) and app_role() = 'team_lead')));

drop policy if exists reviews_read on investigation_reviews;
create policy reviews_read on investigation_reviews for select to audit_app using (
  app_is_admin() or team_id = any (app_team_ids()));
-- Anyone on the team may dispute; only leads and admins approve or reject.
drop policy if exists reviews_write on investigation_reviews;
create policy reviews_write on investigation_reviews for insert to audit_app with check (
  reviewer = app_user_id()
  and (app_is_admin() or team_id = any (app_team_ids()))
  and (decision = 'disputed' or app_is_admin() or app_role() = 'team_lead'));

drop policy if exists feedback_own on answer_feedback;
create policy feedback_own on answer_feedback for all to audit_app
  using (user_id = app_user_id() or app_is_admin()) with check (user_id = app_user_id());

-- Fix requests: the team reads them; a member may create one; only a lead or admin of the
-- team decides it, as themselves. The fix agent's worker scope updates drafting rows.
drop policy if exists fixes_read on fix_requests;
create policy fixes_read on fix_requests for select to audit_app using (
  app_is_admin() or team_id = any (app_team_ids()));
drop policy if exists fixes_create on fix_requests;
create policy fixes_create on fix_requests for insert to audit_app with check (
  (app_is_admin() or team_id = any (app_team_ids())) and status = 'drafting' and approver is null);
drop policy if exists fixes_update on fix_requests;
create policy fixes_update on fix_requests for update to audit_app
  using (app_is_admin() or team_id = any (app_team_ids()))
  with check (
    (app_is_admin() or team_id = any (app_team_ids()))
    and (status not in ('approved','rejected') or approver = app_user_id())
    and (status not in ('approved','rejected') or app_is_admin() or app_role() = 'team_lead')
    -- four eyes: nobody approves their own request, admins included
    and (status <> 'approved' or approver is distinct from requested_by));

drop policy if exists jobs_own on chat_jobs;
create policy jobs_own on chat_jobs for all to audit_app
  using (user_id = app_user_id()) with check (user_id = app_user_id());

drop policy if exists audit_insert on audit_log;
create policy audit_insert on audit_log for insert to audit_app with check (user_id = app_user_id());

-- The ingest role writes every team's data, so it gets an allow-all policy per RLS table.
do $$
declare t text;
begin
  foreach t in array array['findings','finding_events','weekly_aggregates','investigations',
                           'team_notes','session_turns','user_prefs','audit_log','chat_jobs',
                           'investigation_reviews','answer_feedback','fix_requests'] loop
    execute format('drop policy if exists ingest_all on %I', t);
    execute format('create policy ingest_all on %I for all to audit_ingest using (true) with check (true)', t);
  end loop;
end $$;

-- ── Grants ─────────────────────────────────────────────────────────────────
grant usage on schema public to audit_app, audit_ingest;
grant select on teams, repo_owners, runs, run_collectors to audit_app;
grant select on findings, finding_events, weekly_aggregates, investigations, team_notes to audit_app;
grant insert on investigations, team_notes, audit_log to audit_app;
grant select, insert, update, delete on session_turns, user_prefs to audit_app;
grant select, insert, update on chat_jobs to audit_app;
grant select, insert on investigation_reviews, answer_feedback to audit_app;
grant update (status, approver, decided_at) on team_notes to audit_app;
grant select, insert, update on fix_requests to audit_app;
grant select, update (resolved_at, pending) on review_gates to audit_app;
grant execute on function review_state(bigint, boolean) to audit_app, audit_ingest;
grant usage on all sequences in schema public to audit_app;
-- audit_app gets no UPDATE/DELETE on audit_log or investigations: append-only.

grant select, insert, update, delete on all tables in schema public to audit_ingest;
grant usage on all sequences in schema public to audit_ingest;

-- ── Terraform drafter ──────────────────────────────────────────────────────
-- Conventions are the drafter's long-term memory. Anyone in a team may PROPOSE one (and a
-- rejected draft proposes one from the lead's reason); only a lead or admin activates it.
-- team_id null = applies to every team (admins decide those).
create table if not exists infra_conventions (
  id          uuid primary key default gen_random_uuid(),
  team_id     text references teams(id),
  text        text not null check (length(text) between 5 and 500),
  status      text not null default 'proposed' check (status in ('proposed','active','rejected')),
  source      text not null default 'manual' check (source in ('manual','rejection','agent')),
  author      text not null,
  approver    text,
  request_id  uuid,
  created_at  timestamptz not null default now(),
  decided_at  timestamptz
);

-- Every request is also searchable history: what was asked, what was decided, and why a
-- lead rejected it. The drafter recalls similar past requests from here.
create table if not exists infra_requests (
  id              uuid primary key,
  team_id         text not null references teams(id),
  requested_by    text not null,
  request         text not null check (length(request) between 10 and 2000),
  status          text not null default 'drafting'
                  check (status in ('drafting','needs_input','awaiting_approval','approved','rejected','opened','failed')),
  decision        text check (decision in ('reuse','new','refuse')),
  reasoning       text,
  question        text,
  answer          text,
  files           jsonb not null default '[]',   -- [{"path", "content"}]
  diff            text,
  checks          jsonb not null default '[]',   -- [{"name", "ok", "detail"}]
  steps           jsonb not null default '[]',   -- progress labels while drafting
  approver        text,
  decided_at      timestamptz,
  approved_sha256 text,                          -- hash of files at approval; the PR must match it
  reject_reason   text,
  pr_url          text,
  error           text,
  thread_id       text not null,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  search          tsvector generated always as (to_tsvector('english',
                    coalesce(request, '') || ' ' || coalesce(reasoning, '') || ' ' || coalesce(reject_reason, ''))) stored
);
create index if not exists infra_requests_search on infra_requests using gin (search);
-- v3: drafts are requested by security admins for any repo they choose (not per team).
alter table infra_requests add column if not exists repo text;
alter table infra_requests alter column team_id drop not null;
create index if not exists infra_requests_team on infra_requests (team_id, created_at desc);

alter table infra_conventions enable row level security; alter table infra_conventions force row level security;
alter table infra_requests    enable row level security; alter table infra_requests    force row level security;

-- The Terraform drafter is a security-admin tool: only admins see, request, answer and decide.
-- An admin may approve their own draft (the GitHub PR review is the second pair of eyes); the
-- approval is still bound to the exact files they reviewed.
drop policy if exists conventions_read on infra_conventions;
create policy conventions_read on infra_conventions for select to audit_app using (app_is_admin());
drop policy if exists conventions_propose on infra_conventions;
create policy conventions_propose on infra_conventions for insert to audit_app with check (
  status = 'proposed' and approver is null and author = app_user_id() and app_is_admin());
drop policy if exists conventions_decide on infra_conventions;
create policy conventions_decide on infra_conventions for update to audit_app
  using (app_is_admin())
  with check (approver = app_user_id() and status in ('active','rejected') and app_is_admin());

drop policy if exists infra_read on infra_requests;
create policy infra_read on infra_requests for select to audit_app using (app_is_admin());
drop policy if exists infra_create on infra_requests;
create policy infra_create on infra_requests for insert to audit_app with check (
  app_is_admin() and status = 'drafting' and approver is null and requested_by = app_user_id());
drop policy if exists infra_update on infra_requests;
create policy infra_update on infra_requests for update to audit_app
  using (app_is_admin())
  with check (app_is_admin() and (status not in ('approved','rejected') or approver = app_user_id()));

do $$
declare t text;
begin
  foreach t in array array['infra_conventions','infra_requests'] loop
    execute format('drop policy if exists ingest_all on %I', t);
    execute format('create policy ingest_all on %I for all to audit_ingest using (true) with check (true)', t);
  end loop;
end $$;

grant select, insert on infra_conventions to audit_app;
grant update (status, approver, decided_at) on infra_conventions to audit_app;
grant select, insert, update on infra_requests to audit_app;
grant select, insert, update, delete on infra_conventions, infra_requests to audit_ingest;

-- ── Draft integrity ────────────────────────────────────────────────────────
-- RLS says WHICH rows a person may update; it can't say which columns or transitions. A
-- member's scope may update their team's rows (the answer to a drafter question, a failed
-- job), so without this a member could rewrite a draft's content after the lead looked at
-- it, or mark a request "opened" with any link. Only the fix/drafter workers (role 'worker')
-- write draft content and PR results; people only move status along these edges:
--   awaiting_approval -> approved | rejected   (leads; RLS checks who)
--   needs_input -> drafting                    (the answer to the drafter's question)
--   drafting | needs_input -> failed           (a background job that died)
-- The ingest role (maintenance) and the table owner are not restricted.
create or replace function guard_draft_update() returns trigger language plpgsql as $$
declare
  edge text := old.status || '>' || new.status;
  people_edges text[] := array['awaiting_approval>approved','awaiting_approval>rejected',
                               'needs_input>drafting','drafting>failed','needs_input>failed'];
  old_doc jsonb;
  new_doc jsonb;
  locked text[];
begin
  if app_role() = 'worker' or app_user_id() like 'worker:%' or pg_has_role(current_user, 'audit_ingest', 'MEMBER')
     or not pg_has_role(current_user, 'audit_app', 'MEMBER') then
    return new;
  end if;
  if old.status <> new.status and not edge = any (people_edges) then
    raise exception 'status % -> % is not a change a person can make', old.status, new.status
      using errcode = 'insufficient_privilege';
  end if;
  -- everything except the columns a person's decision or answer legitimately sets
  locked := case tg_table_name
    when 'fix_requests' then array['status','approver','decided_at','updated_at','approved_sha256']
    else array['status','approver','decided_at','updated_at','approved_sha256','reject_reason',
               'answer','question','error','search'] end;
  old_doc := to_jsonb(old) - locked;
  new_doc := to_jsonb(new) - locked;
  if old_doc is distinct from new_doc then
    raise exception 'draft content is written only by the agent' using errcode = 'insufficient_privilege';
  end if;
  if new.approved_sha256 is distinct from old.approved_sha256 and new.status <> 'approved' then
    raise exception 'the approval hash is set only by an approval' using errcode = 'insufficient_privilege';
  end if;
  if tg_table_name = 'infra_requests' then
    if (new.answer is distinct from old.answer or new.question is distinct from old.question)
       and edge <> 'needs_input>drafting' then
      raise exception 'answers are accepted only while the drafter is waiting for one'
        using errcode = 'insufficient_privilege';
    end if;
    if new.reject_reason is distinct from old.reject_reason and new.status <> 'rejected' then
      raise exception 'a reject reason goes with a rejection' using errcode = 'insufficient_privilege';
    end if;
  end if;
  if new.error is distinct from old.error and new.status <> 'failed' then
    raise exception 'errors are recorded only with a failure' using errcode = 'insufficient_privilege';
  end if;
  return new;
end $$;

drop trigger if exists fix_requests_guard on fix_requests;
create trigger fix_requests_guard before update on fix_requests
  for each row execute function guard_draft_update();
drop trigger if exists infra_requests_guard on infra_requests;
create trigger infra_requests_guard before update on infra_requests
  for each row execute function guard_draft_update();

-- Step Functions task tokens: only the people who can release a gate (leads, admins) see them.
alter table review_gates enable row level security; alter table review_gates force row level security;
drop policy if exists gates_deciders on review_gates;
create policy gates_deciders on review_gates for all to audit_app
  using (app_role() in ('team_lead','security_admin')) with check (app_role() in ('team_lead','security_admin'));
drop policy if exists ingest_all on review_gates;
create policy ingest_all on review_gates for all to audit_ingest using (true) with check (true);

-- ── Dashboard-managed teams ────────────────────────────────────────────────
-- Teams, members, owned repos/URLs and per-team delivery settings are managed in the web
-- dashboard and take effect immediately: no YAML edit, no Terraform deploy. ownership.yml and
-- Entra group ids still work as a starting point (source = 'config'); a team edited in the
-- dashboard becomes source = 'dashboard' and the YAML no longer touches it.
--
-- Precedence for "whose repo is this": an explicit dashboard assignment (team_assets), then a
-- dashboard rule (team_rules: topic / name prefix / name contains), then ownership.yml.
-- Membership: team_members by e-mail (the sign-in token's e-mail/UPN), plus the legacy Entra
-- group mapping on teams.entra_group_id.
alter table teams add column if not exists source      text not null default 'config';
alter table teams add column if not exists created_by  text;
alter table teams add column if not exists created_at  timestamptz not null default now();
alter table teams add column if not exists archived_at timestamptz;
do $$ begin
  alter table teams add constraint teams_id_format check (id ~ '^[a-z][a-z0-9_]{1,39}$');
exception when duplicate_object then null; when check_violation then null; end $$;
do $$ begin
  alter table teams add constraint teams_source check (source in ('config','dashboard'));
exception when duplicate_object then null; end $$;

create table if not exists team_members (
  team_id   text not null references teams(id) on delete cascade,
  email     text not null check (email = lower(email) and email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' and length(email) <= 254),
  role      text not null default 'member' check (role in ('member','lead')),
  added_by  text not null,
  added_at  timestamptz not null default now(),
  primary key (team_id, email)
);
create index if not exists team_members_email on team_members (email);

-- One owner per asset: assigning a repo or URL to a team moves it.
create table if not exists team_assets (
  kind      text not null check (kind in ('repo','url')),
  value     text not null check (length(value) between 1 and 300),
  team_id   text not null references teams(id) on delete cascade,
  added_by  text not null,
  added_at  timestamptz not null default now(),
  primary key (kind, value),
  check (kind <> 'repo' or value ~ '^[A-Za-z0-9._-]{1,100}$'),
  check (kind <> 'url'  or value ~ '^https?://[^\s/$.?#][^\s]*$')
);
create index if not exists team_assets_team on team_assets (team_id);

create table if not exists team_rules (
  id        bigserial primary key,
  team_id   text not null references teams(id) on delete cascade,
  kind      text not null check (kind in ('topic','name_prefix','name_contains')),
  value     text not null check (value = lower(value) and value ~ '^[a-z0-9._-]{1,100}$'),
  added_by  text not null,
  added_at  timestamptz not null default now(),
  unique (kind, value)
);

-- Delivery: e-mail digest to every member, an optional Slack incoming webhook, optional Jira.
create table if not exists team_settings (
  team_id         text primary key references teams(id) on delete cascade,
  email_digest    boolean not null default true,
  slack_webhook   text check (slack_webhook is null or slack_webhook ~ '^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+$'),
  jira_enabled    boolean not null default false,
  jira_project    text check (jira_project is null or jira_project ~ '^[A-Z][A-Z0-9_]{1,19}$'),
  jira_issue_type text not null default 'Bug' check (length(jira_issue_type) between 1 and 40),
  jira_assignee   text check (jira_assignee is null or jira_assignee ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  sla_days        jsonb not null default '{"critical": 7, "high": 30}',
  updated_by      text,
  updated_at      timestamptz not null default now(),
  check (not jira_enabled or jira_project is not null)
);

-- One Jira ticket per team + source + resource + rule (high and critical only). Written by
-- the weekly delivery step (ingest role); teams read their own.
create table if not exists jira_tickets (
  group_key        text primary key,            -- team|source|resource|rule
  team_id          text not null references teams(id) on delete cascade,
  source           text not null,
  resource         text not null,
  rule             text not null,
  severity         text not null,
  issue_key        text not null,
  status           text not null default 'open' check (status in ('open','closed')),
  fingerprints     text[] not null default '{}',
  created_at       timestamptz not null default now(),
  closed_at        timestamptz,
  last_followup_at timestamptz,
  followups        int not null default 0
);
create index if not exists jira_tickets_team on jira_tickets (team_id, status);

-- Every team change is recorded (who, what, when) for audit.
create table if not exists team_changes (
  id       bigserial primary key,
  team_id  text,
  actor    text not null,
  action   text not null,
  detail   jsonb not null default '{}',
  at       timestamptz not null default now()
);

-- Sign-in looks up a user's memberships before any scope exists, so it goes through this
-- function (owner rights; team_members is not FORCE'd so the owner can read it). It returns
-- only the caller-supplied e-mail's rows.
create or replace function memberships_for(p_email text) returns table (team_id text, team_name text, role text)
language sql stable security definer set search_path = public as $$
  select m.team_id, t.name, m.role from team_members m join teams t on t.id = m.team_id
  where m.email = lower(p_email) and t.archived_at is null order by m.team_id
$$;
revoke all on function memberships_for(text) from public;
grant execute on function memberships_for(text) to audit_app;

-- RLS. Team, member, asset and rule rows are visible to the team (and admins); only admins
-- create teams or move repos/URLs between teams. A lead manages their own team's members
-- (members only; admins make leads) and its delivery settings.
alter table teams         enable row level security;
alter table repo_owners   enable row level security;
alter table team_members  enable row level security;
alter table team_assets   enable row level security;  alter table team_assets   force row level security;
alter table team_rules    enable row level security;  alter table team_rules    force row level security;
alter table team_settings enable row level security;  alter table team_settings force row level security;
alter table jira_tickets  enable row level security;  alter table jira_tickets  force row level security;
alter table team_changes  enable row level security;  alter table team_changes  force row level security;

drop policy if exists teams_read on teams;
create policy teams_read on teams for select to audit_app using (true);
drop policy if exists teams_admin_insert on teams;
create policy teams_admin_insert on teams for insert to audit_app with check (app_is_admin() and source = 'dashboard');
drop policy if exists teams_admin_update on teams;
create policy teams_admin_update on teams for update to audit_app using (app_is_admin()) with check (app_is_admin());

drop policy if exists owners_read on repo_owners;
create policy owners_read on repo_owners for select to audit_app using (true);
drop policy if exists owners_admin_write on repo_owners;
create policy owners_admin_write on repo_owners for insert to audit_app with check (app_is_admin());
drop policy if exists owners_admin_update on repo_owners;
create policy owners_admin_update on repo_owners for update to audit_app using (app_is_admin()) with check (app_is_admin());

drop policy if exists members_read on team_members;
create policy members_read on team_members for select to audit_app using (
  app_is_admin() or team_id = any (app_team_ids()));
drop policy if exists members_insert on team_members;
create policy members_insert on team_members for insert to audit_app with check (
  app_is_admin() or (team_id = any (app_team_ids()) and app_role() = 'team_lead' and role = 'member'));
drop policy if exists members_update on team_members;
create policy members_update on team_members for update to audit_app
  using (app_is_admin()) with check (app_is_admin());
drop policy if exists members_delete on team_members;
create policy members_delete on team_members for delete to audit_app using (
  app_is_admin() or (team_id = any (app_team_ids()) and app_role() = 'team_lead' and role = 'member'));

drop policy if exists assets_read on team_assets;
create policy assets_read on team_assets for select to audit_app using (app_is_admin() or team_id = any (app_team_ids()));
drop policy if exists assets_admin on team_assets;
create policy assets_admin on team_assets for all to audit_app using (app_is_admin()) with check (app_is_admin());

drop policy if exists rules_read on team_rules;
create policy rules_read on team_rules for select to audit_app using (app_is_admin() or team_id = any (app_team_ids()));
drop policy if exists rules_admin on team_rules;
create policy rules_admin on team_rules for all to audit_app using (app_is_admin()) with check (app_is_admin());

drop policy if exists settings_read on team_settings;
create policy settings_read on team_settings for select to audit_app using (app_is_admin() or team_id = any (app_team_ids()));
drop policy if exists settings_write on team_settings;
create policy settings_write on team_settings for insert to audit_app with check (
  app_is_admin() or (team_id = any (app_team_ids()) and app_role() = 'team_lead'));
drop policy if exists settings_update on team_settings;
create policy settings_update on team_settings for update to audit_app
  using (app_is_admin() or (team_id = any (app_team_ids()) and app_role() = 'team_lead'))
  with check (app_is_admin() or (team_id = any (app_team_ids()) and app_role() = 'team_lead'));

drop policy if exists jira_read on jira_tickets;
create policy jira_read on jira_tickets for select to audit_app using (app_is_admin() or team_id = any (app_team_ids()));

drop policy if exists changes_read on team_changes;
create policy changes_read on team_changes for select to audit_app using (app_is_admin() or team_id = any (app_team_ids()));
drop policy if exists changes_insert on team_changes;
create policy changes_insert on team_changes for insert to audit_app with check (actor = app_user_id());

-- Moving a repo/URL re-teams its open findings at once (admins only; column-limited grant).
drop policy if exists findings_admin_reassign on findings;
create policy findings_admin_reassign on findings for update to audit_app using (app_is_admin()) with check (app_is_admin());

do $$
declare t text;
begin
  foreach t in array array['teams','repo_owners','team_members','team_assets','team_rules','team_settings',
                           'jira_tickets','team_changes'] loop
    execute format('drop policy if exists ingest_all on %I', t);
    execute format('create policy ingest_all on %I for all to audit_ingest using (true) with check (true)', t);
  end loop;
end $$;

grant select, insert on teams to audit_app;
grant update (name, archived_at, source, entra_group_id) on teams to audit_app;
grant select, insert on repo_owners to audit_app;
grant update (team_id, source, confidence, approved_by, updated_at) on repo_owners to audit_app;
grant update (team_id) on findings to audit_app;
grant select, insert, update, delete on team_members, team_assets, team_rules to audit_app;
grant select, insert, update on team_settings to audit_app;
grant select on jira_tickets to audit_app;
grant select, insert on team_changes to audit_app;
grant select, insert, update, delete on team_members, team_assets, team_rules, team_settings, jira_tickets,
  team_changes to audit_ingest;
grant usage on all sequences in schema public to audit_app, audit_ingest;
