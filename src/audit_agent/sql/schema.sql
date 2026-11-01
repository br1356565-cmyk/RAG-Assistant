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
  created_at     timestamptz not null default now(),
  unique (fingerprint, evidence_hash, prompt_version)
);

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

drop policy if exists audit_insert on audit_log;
create policy audit_insert on audit_log for insert to audit_app with check (user_id = app_user_id());

-- The ingest role writes every team's data, so it gets an allow-all policy per RLS table.
do $$
declare t text;
begin
  foreach t in array array['findings','finding_events','weekly_aggregates','investigations',
                           'team_notes','session_turns','user_prefs','audit_log'] loop
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
grant usage on all sequences in schema public to audit_app;
-- audit_app gets no UPDATE/DELETE on audit_log or investigations: append-only.

grant select, insert, update, delete on all tables in schema public to audit_ingest;
grant usage on all sequences in schema public to audit_ingest;
