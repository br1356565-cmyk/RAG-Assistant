# Demo stack in the personal AWS account (Sydney), with personal GitHub repos and Entra tenant.
# Terraform loads this file automatically; the deploy-demo workflow uses it unless the
# DEMO_TFVARS secret is set. No secrets here: keys live in Secrets Manager.
# Steps: local/DEPLOY-DEMO.md. Expected cost: ~$25-40/month; destroy after the demo.

aws_region  = "ap-southeast-2"
name_prefix = "audit-demo"

# Network: create everything, with a t4g.micro NAT instance instead of a NAT gateway.
create_vpc        = true
nat_mode          = "instance"
nat_instance_type = "t4g.micro" # Free plan: only free-tier-eligible instance types

# Models: Bedrock directly (no LiteLLM gateway in this account). Claude is not enabled on
# this account, so Amazon Nova Pro (APAC inference profile) for both.
llm_backend       = "bedrock"
chat_model        = "apac.amazon.nova-pro-v1:0"
batch_model       = "apac.amazon.nova-pro-v1:0"
chat_temperature  = "none"
batch_temperature = "none"

# Small and disposable.
db_instance_class        = "db.t3.micro"
db_backup_retention_days = 1 # Free plan maximum
db_deletion_protection   = false
db_skip_final_snapshot   = true
secret_recovery_days     = 0
force_destroy_buckets    = true
log_retention_days       = 7
raw_retention_days       = 30

# New accounts often have a Lambda concurrency limit of 10, which leaves no room to reserve.
chat_reserved_concurrency   = -1
investigate_max_concurrency = 2
max_investigations_per_run  = 20

# Identity: personal Entra tenant (DEPLOY-DEMO.md, step 3).
entra_tenant_id = "42919981-4639-4573-aca3-da94a49690e9"
entra_client_id = "2a5b800c-5fb9-443a-add3-85adad30507e"
allowed_cidrs   = [] # no WAF ($6/month); the app still requires an Entra login
team_group_ids = {
  web      = "29724f6f-c945-455f-b54b-1a8078e43324"
  data     = "a2f0645b-9d61-4b5f-b390-2234f592428e"
  platform = "949d6356-6288-4fbe-8c63-f27ffcf8b644"
}

# GitHub: the read-only App installed on the personal account.
github_org             = "br1356565-cmyk"
github_owner_type      = "user"
github_app_id          = "5594367"
github_installation_id = "178167841"
ownership_config       = "ownership.demo.yml"

# GuardDuty is optional: enable it in the console first, generate sample findings, then add
# "guardduty" here.
collectors        = ["ownership", "dependabot"]
guardduty_regions = ["ap-southeast-2"]

# Agent quality: answers under 70% confidence go back for evidence up to twice; weekly
# investigations still under it wait (up to 72 h) for a team lead in the Review panel.
confidence_threshold      = 0.7
max_confidence_retries    = 2
verify_answers            = true
review_gate_timeout_hours = 72

# AgentCore (DEPLOY-DEMO.md step 6b). false = the all-Lambda design that is deployed today.
agentcore_enabled          = true
agentcore_policy_mode      = "ENFORCE"
agentcore_memory_long_term = false # extraction uses an AgentCore-managed model
agentcore_tracing          = false # needs CloudWatch Transaction Search turned on first

# Fix agent: a second GitHub App with write access, used only for approved fix PRs.
# Until it exists, fixes can be drafted and approved but no PR is opened.
fix_agent_enabled          = true
fix_github_app_id          = null # the fix-bot App ID, as a string
fix_github_installation_id = null # its installation ID, as a string

# Server diagnostics through SSM (read-only checks); off for now.
diagnostics_enabled = false

# Spend guard.
alarm_email        = "rameshbalaji256001@gmail.com"
monthly_budget_usd = 30
