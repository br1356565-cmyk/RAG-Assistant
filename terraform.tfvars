# Demo in a fresh personal AWS account, with your own GitHub repos and a personal Entra
# tenant. Copy to demo.tfvars (git-ignored) and fill in the <...> values.
# Steps: local/DEPLOY-DEMO.md. Expected cost: ~$25/month; destroy after the demo.

aws_region  = "ap-southeast-2"
name_prefix = "audit-demo"

# Network: create everything, with a t4g.nano NAT instance instead of a NAT gateway.
create_vpc = true
nat_mode   = "instance"

# Models: Bedrock directly (no LiteLLM gateway in this account). Use the inference-profile
# ids shown in the Bedrock console (Model catalog -> model -> "Inference profile ID").
llm_backend = "bedrock"
chat_model        = "au.anthropic.claude-sonnet-5-5"
batch_model       = "au.anthropic.claude-haiku-5-5"
chat_temperature  = "none"
batch_temperature = "none"

# Small and disposable.
db_instance_class      = "db.t3.micro"
db_deletion_protection = false
db_skip_final_snapshot = true
secret_recovery_days   = 0
force_destroy_buckets  = true
log_retention_days     = 7
raw_retention_days     = 30

# New accounts often have a Lambda concurrency limit of 10, which leaves no room to reserve.
chat_reserved_concurrency   = -1
investigate_max_concurrency = 2
max_investigations_per_run  = 20

# Identity: your own Entra tenant (see DEPLOY-DEMO.md, step 2).
entra_tenant_id = "42919981-4639-4573-aca3-da94a49690e9"
entra_client_id = "2a5b800c-5fb9-443a-add3-85adad30507e"
allowed_cidrs   = [] # no WAF ($6/month); the app still requires an Entra login
team_group_ids = {
  web      = "29724f6f-c945-455f-b54b-1a8078e43324"
  data     = "a2f0645b-9d61-4b5f-b390-2234f592428e"
  platform = "949d6356-6288-4fbe-8c63-f27ffcf8b644"
}
# GitHub: an App installed on your personal account.
github_org             = "<your GitHub username>"
github_owner_type      = "user"
github_app_id          = "<app id>"
github_installation_id = "<installation id>"
ownership_config       = "ownership.demo.yml"

# GuardDuty is optional: enable it in the console first (trial on the paid plan only), generate sample
# findings, then add "guardduty" here.
collectors        = ["ownership", "dependabot"]
guardduty_regions = ["us-east-1"]

# Spend guard.
alarm_email        = "<your email>"
monthly_budget_usd = 30
