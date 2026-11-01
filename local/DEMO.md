# Local prototype: setup and demo script

Runs on your laptop against your org's real GitHub data and real Bedrock answers.
Nothing is deployed to AWS. Postgres runs in Docker; the code is the same code that
would run in Lambda.

## Setup (about 20 minutes, once)

Needs Docker, Python 3.11+, the GitHub CLI, and network access to your LiteLLM gateway
(or AWS credentials with Bedrock access for the local LiteLLM container).

```bash
cd local
cp .env.example .env
gh auth refresh -s read:org,security_events     # then paste `gh auth token` into GITHUB_TOKEN
# set GATEWAY_URL + GATEWAY_API_KEY to your LiteLLM gateway, with aliases audit-chat and audit-batch
#   ...or edit litellm.yaml and use: docker compose --profile litellm up -d

docker compose up -d                             # Postgres on 127.0.0.1:5433
python -m venv .venv && . .venv/bin/activate
pip install -r ../requirements.txt boto3
python bootstrap.py                              # schema, roles, row-level security
python run_weekly.py --check                     # GitHub budget + token permissions, ~3 requests
python run_weekly.py --max-investigations 15     # collect -> ingest -> investigate -> summary
python dev_server.py                             # http://127.0.0.1:8080
```

Edit `personas.yml` so the personas match the teams you want to show.
Re-running `run_weekly.py` is safe; the second run shows "fixed" and "new" counts.

**GitHub rate limits.** A personal token gets 5,000 requests per hour, shared with
everything else using your account. One run uses roughly:

| Step | Requests |
|---|---|
| Ownership: org repos + 2 team listings | about 10 for 400–500 repos |
| Dependabot: open alerts, 100 per page | open alerts ÷ 100 |
| Investigations: advisory, a file or two, maybe a code search | about 3 each, so about 45 for 15 |

So a run is usually well under 200 requests. Each run prints its count, and `--check` shows
what's left. The client waits when GitHub asks it to, spaces code searches 6.5 s apart (the
code search limit is 10 per minute), and stops with the reset time if the wait would be long.
If today's audit cron uses a token from **your** account, don't run the prototype around
its schedule (Monday 05:30 IST), because both draw on the same hourly budget.

## Before the meeting

- [ ] Run `run_weekly.py` the day before, not live. During the demo only the chat calls the model.
- [ ] Read the top investigations for the teams you'll show. If one is wrong, keep it in and
      say so. "Here's where it's uncertain" builds more trust than a perfect-looking demo.
- [ ] Note the LiteLLM spend for the run's key: real cost beats an estimate.
- [ ] Take screenshots of each step as a fallback if VPN or the gateway misbehaves.
- [ ] Have today's Monday audit email open for the before/after comparison.

## Demo (about 10 minutes)

1. **Today (1 min).** Open the current Monday email: a list of SharePoint links per team.
   Point out that nobody can see what's new, what's fixed or what to do first without
   opening spreadsheets.
2. **A team lead's Monday (2 min).** Persona *App Engineering lead*. The "This week"
   panel shows real counts, the top items with real ages, a plain-language explanation
   and the exact fix version.
3. **Ask (2 min).** Click "What should we fix first this week?". The answer cites
   findings by id; every claim traces back to data.
4. **Isolation (2 min).** Switch to *Growth Engineering engineer*. Different data. Ask
   about the App Engineering finding by id: it is refused. The database enforces this,
   not the prompt.
5. **The gap nobody sees today (1 min).** Switch to *Security admin*. Show the unowned
   repos count. These repos appear in no team's report today, including the 9 `india-cms`
   overrides.
6. **Operations (1 min).** Show the run summary from `run_weekly.py` (what goes to Slack),
   including how a failed collector is reported instead of silently skipped.
7. **The ask (1 min).** Ask for something small and specific, for example: *a four-week pilot
   with one team, keeping the current email running in parallel.*

## Questions to expect

| Question | Answer |
|---|---|
| Why not just improve the email? | The brief *is* the new email; chat is optional. The real change is tracking findings over time and one owner per repo. |
| What does it cost? | Show the LiteLLM spend from the prototype run. Investigations only run for new or changed critical/high findings, capped per run and cached; chat costs per question. |
| Is it safe to send vulnerability data to an LLM? | Bedrock in our own AWS account, through our existing gateway and its guardrails. No leaked-secret findings are sent. Every question is logged with who asked and what was shown. |
| What if it's wrong? | Code decides what is a finding and how it ranks; the model only explains. Answers cite finding ids and investigations must cite what they looked at. Confidence is shown. |
| Who maintains it? | Serverless on AWS, one Terraform apply, automated tests. It reuses the LiteLLM gateway we already run. The old cron keeps running until each report is ported. |
| What's needed for production? | A GitHub App, an Entra app registration, an RDS `db.t3.small`, and one Terraform apply. See the main README. |

## What the prototype doesn't show

- Entra ID sign-in (personas stand in for it; everything after sign-in is the production path)
- Step Functions, CloudFront, IAM and RDS IAM login (they need an AWS deployment)
- Reports not yet ported: README, branch divergence, enforcement, inactive users and repos, VPN, Security Hub
