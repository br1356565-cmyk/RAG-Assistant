# DevOps Audit Agent

The next version of DevOps Audit Automation: findings tracked over time in Postgres,
owned by exactly one team, explained by an agent, and queryable by each team through a
chat page that only shows them their own data. Everything, including the code, ships
with `terraform apply`.

```
EventBridge Scheduler (Mon 00:00 UTC)
  -> Step Functions
       Collect     ownership | dependabot | guardduty   (Lambda, outside VPC -> S3)
       Ingest      lifecycle, owners, aggregates, queue (Lambda, VPC -> RDS)
       Investigate one finding per item, bounded parallel (Lambda; confidence gate)
       ReviewGate  waits (task token) until a team lead reviews every low-confidence investigation
       Notify      Slack run summary, including failures and review status
CloudFront (+ optional WAF IP allowlist)
  /       -> S3 web app (Entra ID sign-in, PKCE): brief, chat with live steps, Review panel
  /api/*  -> chat Lambda function URL: auth, background chat jobs, review / feedback / fix API
               -> AgentCore Runtime "audit" (HTTP, Entra JWT authorizer): the ReAct harness
                    memory  -> AgentCore Memory (per user, per session; optional long-term)
                    tools   -> in-process DB tools (row-level security)
                            -> AgentCore Gateway (MCP, IAM) + Policy (Cedar, default deny)
                                 -> tools Lambda: GitHub read, SSM diagnostics, open approved fix PR
                    fixes   -> AgentCore Runtime "fix" (A2A): LangGraph, interrupt for approval
RDS PostgreSQL: findings, owners, reviews, fix requests, checkpoints, audit log; isolation by RLS
CloudWatch: metric filters on structured logs, dashboard, alarms; optional OTel traces
```

`agentcore_enabled = false` keeps the original all-Lambda design (tools in-process, memory
in Postgres, no fix agent); the same code runs either way.

## Try it locally first

`local/` runs the whole pipeline and the web page on a laptop against real GitHub data and
Bedrock, with personas instead of Entra sign-in. Setup and a demo script: `local/DEMO.md`.

## Demo in a personal AWS account

`local/DEPLOY-DEMO.md` deploys the full stack to your own account with your own GitHub repos
and Entra tenant: `create_vpc` (NAT instance), `llm_backend = "bedrock"` (no gateway),
`github_owner_type = "user"`, and a budget alarm, all set in `terraform/demo.tfvars.example`.
About $25/month; `terraform destroy` removes everything.

## Repository layout

```
src/audit_agent/
  collectors/          ownership.py, dependabot.py, guardduty.py (+ base.py: the contract)
  data/ownership.yml   repo -> team rules and overrides (edit by PR)
  sql/schema.sql       tables, roles, row-level security (applied by the migrate Lambda)
  ingest.py            finding lifecycle and investigation queue
  harness.py           the agent loop and its guarantees (citation check, confidence gate)
  verifier.py          scores an answer against the evidence (the confidence gate's judge)
  tools/               the agent's tools (findings, notes, GitHub, diagnostics, request_fix)
  scope_token.py       HMAC-signed caller scope for tools behind the Gateway
  gateway_client.py    MCP client for AgentCore Gateway (SigV4)
  handlers/            Lambda entry points: collect, ingest, investigate, chat (+ api.py:
                       reviews, feedback, fixes), review_gate, gateway_tools, notify, migrate
src/fix_agent/         LangGraph fix agent: deterministic manifest edits, approval interrupt,
                       the GitHub write tool (approved + content-hash bound), A2A server
src/agent_main.py      AgentCore Runtime entry point (chat agent, streams steps)
src/fix_main.py        AgentCore Runtime entry point (fix agent, A2A)
web/                   static page (no dependencies)
terraform/             the whole stack, code included (agentcore.tf, diagnostics.tf, ...)
evals/                 golden questions, replay + live scoring, fix-agent eval (CI gate)
local/                 laptop prototype: docker-compose, run_weekly.py, dev_server.py
tests/                 138 tests against real Postgres with a scripted model
.github/workflows/     evals (every push), deploy-demo (manual), deploy (company)
```

## What is ported from the old tool

| Old report | Status |
|---|---|
| Team classification (3 copies + `override.yml`) | Ported to `ownership.yml` + one collector; one owner per repo |
| Dependabot alerts summary (all team variants) | Ported; now per alert with package, manifest, scope and fix version |
| GuardDuty findings | Ported; non-archived findings across the same 7 regions |
| README, branch divergence, Dependabot/Gitleaks enforcement, visibility, inactive users and repos, new repos, VPN, Security Hub, action metrics | **Not yet.** Keep the existing GitHub Actions cron running for these |

Adding a collector: write `collect(...) -> CollectorOutput` in `collectors/`, add a branch in
`handlers/collect.py`, add its name to `var.collectors`. Ingest, the tools and the UI need no change.

**Behaviour changes to tell teams about**
- A repo now has exactly one owner (first matching rule wins). Before, a repo could appear in
  several teams' reports.
- Repos that match no rule go to an unowned queue for security admins instead of "India".
  Set `fallback_team: india` in `ownership.yml` to keep the old behaviour.
- The 9 `india-cms` overrides point at a team that was never a report category. They stay
  unowned until that team is added to `ownership.yml` or the overrides change.

## First deployment

**1. GitHub App** (replaces the personal access token). Permissions: Repository → Contents
read, Metadata read, Dependabot alerts read; Organization → Members read. Install it on
the org; note the App ID, installation ID, and download the private key.

**2. Entra ID app registration** (one app for the web page and the API)
- Platform: Single-page application (redirect URI comes from step 5)
- Expose an API: scope `access_as_user`
- App roles: `security.admin`, `team.lead`
- Token configuration: groups claim → security groups, "groups assigned to the application"
- Manifest: `"accessTokenAcceptedVersion": 2` (token audience then equals the client ID)
- Assign each team's Entra group to the enterprise application, and put each group's object
  ID in `ownership.yml` under `entra_group_id`

**3. LiteLLM gateway:** add model aliases `audit-chat` (Sonnet-class) and `audit-batch`
(Haiku-class), and a virtual key per team plus a `default` key.

**4. Apply.** The machine running Terraform needs Terraform ≥ 1.6, Python 3 with pip, and `zip`
(the Lambda dependency layer is built locally).
```
cd terraform
cp backend.hcl.example backend.hcl            # state bucket
cp terraform.tfvars.example terraform.tfvars  # VPC, subnets, gateway, Entra, GitHub App
terraform init -backend-config=backend.hcl
terraform apply
```
The apply creates RDS, runs the schema migration, deploys every Lambda behind a `live`
alias, the workflow and its schedule, CloudFront, and the web page.

**5. After the first apply**
- Set the three secret values listed in output `secrets_to_populate`.
- Register output `entra_redirect_uri` as the SPA redirect URI.
- If GuardDuty lives in a security account, let that account's audit role trust output
  `collector_role_arn`, and set `security_audit_role_arn`.
- Run once by hand:
  `aws stepfunctions start-execution --state-machine-arn <state_machine_arn> --input '{"collectors":["ownership","dependabot","guardduty"]}'`

**Rollback a bad release:** `aws lambda update-alias --function-name devops-audit-<fn> --name live --function-version <previous>`.
The next `terraform apply` moves it forward again.

## How team isolation works

1. The chat Lambda verifies the Entra token itself; groups → teams, app roles → role.
2. Every query runs in a transaction that sets `app.team_ids`, `app.role` and `app.user_id`
   for that transaction only.
3. Row-level security in `schema.sql` filters every table on those settings. No settings, no rows.
4. Tools take no team from the model; `team` arguments can only narrow. Repo tools check
   `repo_owners` first. The investigate worker is scoped to the finding's team.

`tests/test_rls.py` proves step 3 with queries that have no `WHERE` clause.

## Agent guarantees

| Guarantee | Where |
|---|---|
| Rounds, tokens and the deadline are capped; out of budget still ends cleanly | `harness.py` |
| Tool errors and bad arguments go back to the model; nothing crashes the run | `_run_tool` |
| Repo, advisory and server-log text is labelled as untrusted data | `untrusted=True` tools |
| Chat may cite only findings retrieved this turn | `_uncited` |
| Answers below `confidence_threshold` go back for evidence, at most `max_confidence_retries` times, then are flagged to the user | `harness.py`, `verifier.py` |
| Investigations end only via `submit_investigation`; low confidence retries, then waits for a lead | `tools/submit.py`, `review_gate.py` |
| Tools behind the Gateway get the caller's scope as a signed token, never from the model | `scope_token.py`, `gateway_tools.py` |
| Which agent may call which Gateway tool is a Cedar policy (default deny) | `terraform/agentcore.tf` |
| The only write (a PR) needs a lead's approval, bound to the exact content approved | `fix_agent/github_write.py` |
| Diagnostics are fixed read-only checks on tagged instances; no shell | `tools/diagnostics.py`, `diagnostics.tf` |
| A failed or partial collector never marks findings fixed | `ingest.py` |
| Every request leaves an audit-log row with every finding id shown to the model | `memory.write_audit` |

## Human review

| What | Who | How |
|---|---|---|
| Low-confidence investigation | team lead / admin | Review panel → approve (optionally correct the fix) or reject; the weekly run waits for it |
| Investigation in the brief | any team member | "This is wrong" → hidden from the brief, re-investigated next run |
| Team note proposed by the agent | team lead / admin | Review panel → approve or reject |
| Fix PR drafted by the fix agent | team lead / admin | Review panel shows the diff → "Approve and open PR" |
| Chat answer | the asker | 👍 / 👎 with an optional comment (dashboard metric) |

Who may decide is enforced by row-level security policies, not by the API code.

## Memory

| Kind | Where | Written by |
|---|---|---|
| Session (short-term) | AgentCore Memory events (or `session_turns` without AgentCore) | Chat |
| User preferences, summaries (long-term, optional) | AgentCore Memory strategies; recalled as context, never as evidence | AgentCore |
| Investigation | `investigations` + append-only `investigation_reviews` | Investigate, leads |
| Team knowledge | `team_notes` | Agent proposes; a team lead approves |
| Fix agent state | LangGraph checkpoints in Postgres (survives the approval wait) | Fix agent |

## Evals

```
python evals/run.py                  # replay: the CI gate (isolation 100%, grounding 100%)
python evals/run.py --model live     # the same 30 questions with your real model (local/.env)
python evals/fix_eval.py             # manifest edits + draft -> approve -> PR
```

## Tests

```
pip install -r requirements-runtime.txt pytest
TEST_PG_HOST=localhost TEST_PG_PORT=5432 pytest -q     # needs Postgres 15+, user postgres
```

## Not built yet

- Remaining collectors (table above); keep the old cron for them
- The weekly brief email
- Token-by-token streaming of the answer text (steps stream; the answer arrives whole)
- RDS certificate verification (`sslmode=require` encrypts but doesn't verify the server)
- Fixes for ecosystems other than npm `package.json` and pip `requirements*.txt`
