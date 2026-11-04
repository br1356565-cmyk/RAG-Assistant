# Deploying the demo to a personal AWS account

The full stack (CloudFront, Lambda, Step Functions, RDS) runs in your own account, with
your own GitHub repos and your own Entra tenant. No Forbes data, no company identity, no
internal LiteLLM gateway. The code and Terraform are the same as production; only
`demo.tfvars` differs.

**Cost:** about $25/month, mostly RDS db.t3.micro (~$12) and the NAT instance with its
public IPv4 (~$7). Lambda, Step Functions, S3 and CloudFront are under $1 at demo volume.
Model tokens are a few dollars. Destroy it when you're done.

Expect about 2 hours the first time: 1 hour of setup, then roughly 15 minutes of apply.

---

## 0. Check the account first (10 min)

- **Credits:** go to Billing → Credits and open "Applicable products". If Claude on Bedrock
  isn't covered, model calls go to your card. At demo volume that's a few dollars.
- **Free plan vs paid plan:** a Free-plan account blocks some services. If an apply fails
  with a message about your account plan, upgrade to the paid plan (Billing → Upgrade).
  Your remaining credits carry over.
- **Lambda concurrency:** go to Service Quotas → AWS Lambda → "Concurrent executions".
  New accounts often start at 10. `demo.tfvars` already avoids reserved concurrency;
  request 100 if you want headroom.
- **CloudFront:** some brand-new accounts must be verified before they can create a
  distribution. If the apply fails on `aws_cloudfront_distribution` with a verification
  message, open a support case (Account and billing, free), then apply again.

Never deploy with the root user. Turn on MFA for root, then work as an IAM user.

## 1. Choose where Terraform runs

- **GitHub Actions (recommended if you don't want to install anything).** Push this
  project to a private repo in your GitHub account, then follow step 5A. The workflows
  build, test and deploy on GitHub's runners. All you need is a browser.
- **Your laptop.** Needs Terraform ≥ 1.6, AWS CLI v2, Python 3 with pip, `zip` and `gh`;
  follow step 5B. On Windows, use WSL.

## 2. Bedrock model access (10 min)

1. Open Bedrock in us-east-1 → **Model catalog**. Pick a Sonnet-class and a Haiku-class
   Claude model.
2. The first time you use Anthropic models, Bedrock may ask for a short use-case form. Fill
   it in.
3. Open each model in the **Playground** and send one message. This confirms access before
   the Lambdas depend on it.
4. Copy each model's **inference profile ID** (it starts with `us.anthropic.`) into
   `chat_model` / `batch_model` in `demo.tfvars`.

## 3. Entra tenant and app registration (25 min)

A free Azure account comes with an Entra ID tenant (portal.azure.com → Microsoft Entra ID).

1. **App registrations → New registration.** Name it `audit-demo`, single tenant, and leave
   the redirect URI empty for now. Note the **Application (client) ID** and **Directory
   (tenant) ID**.
2. **Expose an API:** set the Application ID URI to `api://<client id>` and add the scope
   `access_as_user` (admins and users can consent).
3. **Manifest:** set `"requestedAccessTokenVersion": 2`. In the older manifest view this
   field is called `accessTokenAcceptedVersion`. Version 2 makes the token's audience the
   client ID, which the API checks.
4. **App roles:** create `security.admin` and `team.lead` (allowed member types: Users).
5. **Token configuration → Add groups claim → Security groups**, for the access token.
   The company setup uses "Groups assigned to the application", but assigning groups to an
   app needs Entra ID P1. "Security groups" works on the free tier.
6. **Groups:** create `audit-web`, `audit-data` and `audit-platform`, and copy each
   **Object ID** into `team_group_ids`.
7. **Users** (for showing persona isolation): create two test users, e.g. `asha@<tenant>`
   in `audit-web` and `dev@<tenant>` in `audit-data`. Then go to Enterprise applications →
   `audit-demo` → Users and groups and give **yourself** the `security.admin` role.

## 4. GitHub App and demo repos (20 min)

1. **Seed the repos.** This creates (or, if they exist, updates) four private repos with
   deliberately vulnerable code and outdated dependencies from `local/demo-repos/`, and turns
   on Dependabot alerts, which appear within a few minutes. `local/demo-repos/SCENARIOS.md`
   lists what to try with each agent and what should happen.
   - **From Actions:** create a fine-grained personal access token (Settings → Developer
     settings → Fine-grained tokens). Set it to all repositories, Administration: Read and
     write, Contents: Read and write, and a 7-day expiry. Save it as the repository secret
     `SEED_TOKEN`, then run **Actions → seed-demo-repos → Run workflow**. Delete the token
     afterwards.
   - **From a laptop:** `bash local/seed_demo_repos.sh`.
2. **Create the App:** GitHub → Settings → Developer settings → GitHub Apps → New.
   - Homepage URL: anything. **Webhook:** untick "Active".
   - Repository permissions: **Contents: Read**, **Metadata: Read**, **Dependabot alerts:
     Read**.
   - "Only on this account".
   - Note the **App ID**, then **Generate a private key** (a `.pem` downloads).
3. **Install it** on your account, choosing the four `demo-*` repos. The installation ID
   is the number at the end of the URL: `github.com/settings/installations/<id>`.

## 5A. Deploy from GitHub Actions (nothing installed locally)

**AWS credentials for the workflow.** Pick one.

- **IAM user with access keys (simplest).** In IAM → Users, create `audit-demo-deployer`
  with *no* console access and attach `AdministratorAccess`. Use broad rights only in this
  throwaway account: the stack creates IAM roles, a VPC, RDS and CloudFront. Then open
  Security credentials → Create access key → "Application running outside AWS". Save the
  two values as the repository secrets `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
  Delete the key when the demo is over: it's a long-lived key sitting in GitHub.
- **GitHub OIDC role (no stored key, about 5 more minutes in the console).**
  1. IAM → Identity providers → Add provider → OpenID Connect. URL
     `https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`.
  2. IAM → Roles → Create role → Web identity. Choose that provider, enter your GitHub
     username as the organization, this repo's name, and branch `main`. Attach
     `AdministratorAccess`.
  3. Save the role ARN as the repository **variable** `AWS_ROLE_ARN`. When it is set, the
     workflow uses it instead of keys.

**Repository settings** (Settings → Secrets and variables → Actions):

| Kind | Name | Value |
|---|---|---|
| Variable | `AUDIT_AGENT_DEMO` | `true`, so the company `deploy.yml` only runs tests here |
| File or secret | `terraform/terraform.tfvars` (committed) or the `DEMO_TFVARS` secret | Your filled-in variables: copy `terraform/demo.tfvars.example` to `terraform/terraform.tfvars` and replace every `<...>`. The secret wins if both exist; use it instead of committing if the repo is public and you don't want the email and Entra IDs in it |
| Secret | `GH_APP_PRIVATE_KEY` | The contents of the GitHub App `.pem` file, including the BEGIN/END lines |
| Secret | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Unless you use `AWS_ROLE_ARN` |
| Variable (optional) | `AWS_REGION`, `TF_STATE_BUCKET` | Defaults: `us-east-1`, `audit-demo-tfstate-<account id>` |

**Run it:** Actions → **deploy-demo** → Run workflow, from `main`.

1. `action = plan` first. It runs the tests, creates the state bucket on the first run and
   shows `Plan: N to add` in the run summary. Expect around 80 resources.
2. Every push to `main` now tests, runs the eval gate and applies (pushes touching only docs or `local/` are skipped). For the first deploy you can also run it by hand: `action = apply`, with **run_collection** ticked. It deploys (about 15 minutes),
   uploads the GitHub App key to Secrets Manager and starts the first collection run. The
   run summary shows the web URL and the Entra redirect URI.
3. Continue at step 6, items 1 and 2. The key upload and first run are already done.

A failed apply is safe to re-run; the workflow never runs two applies at once.
`action = destroy` removes everything except the state bucket.

## 5B. Deploy from a laptop (20 min, mostly waiting)

```bash
cd terraform
# State bucket (once). The name must be globally unique.
aws s3api create-bucket --bucket <you>-tfstate-<account id> --region us-east-1
aws s3api put-bucket-versioning --bucket <you>-tfstate-<account id> --versioning-configuration Status=Enabled
cat > backend.hcl <<EOF
bucket = "<you>-tfstate-<account id>"
key    = "audit-demo/terraform.tfstate"
region = "us-east-1"
EOF

cp demo.tfvars.example demo.tfvars        # fill in the <...> values
terraform init -backend-config=backend.hcl
terraform plan -var-file=demo.tfvars -out tfplan
terraform apply tfplan
```

RDS and CloudFront take most of the time. The apply runs the database migration itself.
On a fresh VPC the migration waits for the NAT instance to finish booting (up to about a
minute and a half). If it still times out, run `terraform apply -var-file=demo.tfvars` again.

## 6. After the apply

With 5A, the key upload and the first run were done by the workflow, so only items 1 and
2 below apply. With 5B:

```bash
# GitHub App key: the only secret the demo needs (no LiteLLM keys, no Slack)
aws secretsmanager put-secret-value \
  --secret-id "$(terraform output -json secrets_to_populate | jq -r .github_private_key | cut -d' ' -f1)" \
  --secret-string file://path/to/your-app.private-key.pem

terraform output entra_redirect_uri
```

1. In Entra, open the app → **Authentication → Add a platform → Single-page application**,
   and paste the redirect URI.
2. Confirm the SNS email subscription and the budget alerts.
3. Run the first collection now instead of waiting for Monday:

```bash
aws stepfunctions start-execution \
  --state-machine-arn "$(terraform output -raw state_machine_arn)" \
  --name "first-run-$(date +%s)" \
  --input '{"collectors": ["ownership", "dependabot"]}'
```

Watch it in the Step Functions console. It takes about 2–4 minutes for 4 repos and up to
20 investigations. The Notify step logs that Slack isn't configured; that's expected.

Then open `terraform output -raw web_url` and sign in. Sign in as each user in turn to show
the isolation:
- **Yourself (security.admin):** every team plus the unowned `demo-scratch`.
- **asha (web):** only `demo-shop-web`.
- **dev (data):** only `demo-etl-jobs`.

The talking points and Q&A are in `DEMO.md`.

**Optional GuardDuty:** enable GuardDuty in us-east-1 (the 30-day trial applies only on the
paid account plan; on the Free plan it draws from credits, which is cents for a demo account), then go to
Settings → **Generate sample findings**. Add `"guardduty"` to `collectors` and apply.
Sample findings go to the platform team.

## 6b. AgentCore, human review and the fix agent

With `agentcore_enabled = true` (the default) the same apply also creates two AgentCore
Runtimes (chat agent, fix agent), Memory, a Gateway with one target per tool, and a Cedar
policy engine. Before the first apply:

1. **Region:** check that Bedrock AgentCore (Runtime, Gateway, Memory and Policy) is offered
   in your region in the console. If something is missing there, set
   `agentcore_enabled = false`: everything else, including human review, still works, with
   tools in-process and memory in Postgres (no fix agent).
2. **Entra token audience:** the Runtime's JWT authorizer accepts only access tokens whose
   audience is `entra_client_id`. That needs `"accessTokenAcceptedVersion": 2` in the app
   manifest (step 3 already sets it).
3. **Team leads:** approvals need the `team.lead` app role. In Entra → Enterprise
   applications → your app → Users and groups, assign one demo user the **team.lead** role
   (and keep yourself **security.admin**).
4. **Fix-bot GitHub App (optional, for real PRs):** create a *second* GitHub App with
   repository permissions **Contents: Read and write**, **Pull requests: Read and write**,
   **Metadata: Read**, and no webhook. Install it on the demo repos only. Put its App ID and
   installation ID in `fix_github_app_id` / `fix_github_installation_id`, and its private key
   in the `FIX_GH_APP_PRIVATE_KEY` repository secret (5A) or in the secret named by
   `terraform output secrets_to_populate` (5B). Without it, fixes can still be drafted and
   approved; opening the PR fails with a clear message. The read-only App never gets write access.
5. **Tracing (optional):** `agentcore_tracing = true` adds OpenTelemetry traces of every
   agent run. Turn on CloudWatch **Transaction Search** once per account first (CloudWatch →
   Application Signals → Transaction Search → Enable).
6. **Diagnostics (optional):** `diagnostics_enabled = true`, `diagnostics_demo_instance = true`
   and `diagnostics_demo_team = "web"` create one t4g.micro (no inbound ports) the chat agent
   can run read-only checks on through SSM ("is nginx up on our server?").

**Demo script for review and fixes**
- As **asha** (member): open a critical Dependabot item in the brief → **Draft a fix**. The
  agent drafts the package.json change. Click **Review**: the diff is there, but asha can't approve it.
- As the **team lead**: **Review → Approve and open PR**. The PR appears in the demo repo
  (or, without the fix-bot App, an explanation of what is missing).
- As asha: click **This is wrong** on an investigation. It disappears from the brief and
  shows up in the lead's Review panel; the next weekly run re-investigates it.
- Ask something the data can't support ("will upgrading break our build?"). The page shows
  the agent going back for evidence, then a "not fully sure" note listing what it couldn't verify.
- `terraform output -raw dashboard_url`: questions, low-confidence rate, latency, feedback,
  tokens, review queue, Gateway refusals.

## 7. Pause or tear down

- **Pause between demos:** stop the RDS instance (it restarts by itself after 7 days) and
  the NAT instance. Chat fails while they're stopped. Start them again before the demo.
- **Tear down:** run the deploy-demo workflow with `action = destroy`, or run `terraform destroy -var-file=demo.tfvars`. The demo settings delete
  the buckets, skip the final snapshot and delete secrets immediately, so a later apply
  starts clean. Delete the state bucket last, and the demo repos with
  `gh repo delete <you>/demo-shop-web --yes` (needs `gh auth refresh -s delete_repo`).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ReservedConcurrentExecutions ... below its minimum value` | Account concurrency limit is 10 | Keep `chat_reserved_concurrency = -1`, or raise the quota |
| `aws_cloudfront_distribution`: account must be verified | New-account check | Support case, then apply again |
| Chat answers "The assistant is unavailable" | Bedrock access or a wrong model ID | Check the chat function's logs for `AccessDeniedException` / `ValidationException`; redo step 2 |
| Investigations `failed`, chat works | Usually the GitHub key secret isn't set yet | Step 6; then run the state machine again |
| Ownership run finds 0 repos | App not installed on the repos, or `github_owner_type` isn't `user` | Check the installation's repository access |
| Dependabot collector warns "disabled in N repos" | Alerts are off in those repos | Repo Settings → Code security → Dependabot alerts |
| 403 "group overage" on login | The user is in more than 200 groups | Not expected in a demo tenant |
| Login loops back to Microsoft | Redirect URI missing or added as "Web" | It must be a **Single-page application** redirect |
| Runtime create fails on the code package | The arm64 dependency build failed or the zip is too large | Check the `terraform_data.runtime_build` output; `agentcore_tracing = false` makes it smaller |
| Chat steps stop at "Thinking" and the answer errors with 401 | The Runtime's JWT authorizer refused the token | Token audience must be `entra_client_id` (`accessTokenAcceptedVersion: 2`); check the discovery URL's tenant |
| Tool steps say "refused" | Scope token missing or expired, or Gateway Policy denied the call | `terraform output agentcore` shows `policy_mode`; set `agentcore_policy_mode = "LOG_ONLY"` to see what Policy would deny |
| "Approve and open PR" says the fix agent failed | Fix-bot App not configured, or not installed on that repo | Step 6b.4 |
| Weekly run sits in ReviewGate | Low-confidence investigations wait for a lead (up to `review_gate_timeout_hours`) | Review them in the page, or wait for the timeout; the summary is sent either way |
| Everything AgentCore fails in your region | Service not offered there | `agentcore_enabled = false` |
