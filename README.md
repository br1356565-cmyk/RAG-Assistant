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
       Investigate one finding per item, max 5 parallel  (Lambda, VPC -> RDS, LiteLLM, GitHub)
       Notify      Slack run summary, including failures
CloudFront (+ WAF IP allowlist)
  /       -> S3 web app (Entra ID sign-in, PKCE)
  /api/*  -> chat Lambda function URL (origin access control) -> RDS + LiteLLM -> Bedrock
RDS PostgreSQL db.t3.small: findings, owners, memory, audit log; team isolation by row-level security
```

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
  harness.py           the agent loop and its guarantees
  tools/               the agent's tools
  handlers/            Lambda entry points: collect, ingest, investigate, chat, notify, migrate
web/                   static chat page (no dependencies)
terraform/             the whole stack, code included
local/                 laptop prototype: docker-compose, run_weekly.py, dev_server.py
tests/                 78 tests against real Postgres with a scripted model
.github/workflows/     test -> terraform fmt/validate/plan -> apply on main
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
| Rounds, tokens and the Lambda deadline are capped; out of budget still ends cleanly | `harness.py` |
| Tool errors and bad arguments go back to the model; nothing crashes the run | `_run_tool` |
| Repo and advisory text is labelled as untrusted data | `untrusted=True` tools |
| Chat may cite only findings retrieved this turn | `_uncited` |
| Investigations end only via `submit_investigation`; every source must have been retrieved | `tools/submit.py` |
| Findings are re-investigated only when evidence or `PROMPT_VERSION` changes | `memory.py`, `ingest.py` |
| A failed or partial collector never marks findings fixed | `ingest.py` |
| Every request leaves an audit-log row with every finding id shown to the model | `memory.write_audit` |

## Memory

| Kind | Where | Written by |
|---|---|---|
| Session (short-term) | `session_turns`, 7 days | Chat |
| Investigation | `investigations`, by evidence hash + prompt version | Investigate |
| Team knowledge (long-term) | `team_notes` | Agent proposes; a team lead approves (approval UI not built yet) |

## Tests

```
pip install -r requirements.txt pytest boto3
TEST_PG_HOST=localhost TEST_PG_PORT=5432 pytest -q     # needs Postgres 15+, user postgres
```

## Not built yet

- Remaining collectors (table above); keep the old cron for them
- Approval UI for proposed team notes; the weekly brief email
- Response streaming (Python Lambdas need the Lambda Web Adapter)
- RDS certificate verification (`sslmode=require` encrypts but doesn't verify the server)
