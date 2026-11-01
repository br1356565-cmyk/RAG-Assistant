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
chat_model  = "<Sonnet-class inference profile id, e.g. us.anthropic....>"
batch_model = "<Haiku-class inference profile id>"

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
entra_tenant_id = "<tenant id>"
entra_client_id = "<application (client) id>"
allowed_cidrs   = [] # no WAF ($6/month); the app still requires an Entra login
team_group_ids = {
  web      = "<object id of group 'audit-web'>"
  data     = "<object id of group 'audit-data'>"
  platform = "<object id of group 'audit-platform'>"
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
