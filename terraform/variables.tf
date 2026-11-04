variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type        = string
  default     = "devops-audit"
  description = "Prefix for every resource name."
}

variable "tags" {
  type    = map(string)
  default = {}
}

# ── Network ──────────────────────────────────────────────────────────────────
# Either use an existing VPC (vpc_id + private_subnet_ids with a NAT route), or set
# create_vpc = true for a fresh account: two private subnets, one public subnet and a NAT.
variable "create_vpc" {
  type    = bool
  default = false
}

variable "vpc_cidr" {
  type        = string
  default     = "10.42.0.0/16"
  description = "Only with create_vpc."
}

variable "nat_mode" {
  type        = string
  default     = "instance"
  description = "Only with create_vpc. \"instance\": a t4g.nano NAT instance (~$3/month + public IPv4, single point of failure, fine for a demo). \"gateway\": a managed NAT gateway (~$33/month + data)."
  validation {
    condition     = contains(["instance", "gateway"], var.nat_mode)
    error_message = "nat_mode is \"instance\" or \"gateway\"."
  }
}

variable "nat_instance_type" {
  type        = string
  default     = "t4g.nano"
  description = "Only with nat_mode = \"instance\". Must be Graviton (arm64). Free-plan accounts only allow free-tier-eligible types: use t4g.micro."
  validation {
    condition     = can(regex("^[a-z]+[0-9]+g[a-z]*\\.", var.nat_instance_type))
    error_message = "Use a Graviton (arm64) type such as t4g.nano or t4g.micro; the NAT AMI is arm64."
  }
}

variable "vpc_id" {
  type    = string
  default = null
}

variable "private_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Existing private subnets with a NAT route (when create_vpc = false). Lambdas here reach RDS, the model endpoint, GitHub and Secrets Manager."
}

variable "private_route_table_ids" {
  type        = list(string)
  default     = []
  description = "If set, an S3 gateway endpoint is attached to these route tables (free; keeps S3 traffic off the NAT). Automatic with create_vpc."
}

# ── Model backend ────────────────────────────────────────────────────────────
variable "llm_backend" {
  type        = string
  default     = "gateway"
  description = "\"gateway\": the LiteLLM gateway (chat_model/batch_model are its aliases). \"bedrock\": Bedrock Converse directly (they are Bedrock model or inference-profile ids)."
  validation {
    condition     = contains(["gateway", "bedrock"], var.llm_backend)
    error_message = "llm_backend is \"gateway\" or \"bedrock\"."
  }
}

# ── LiteLLM gateway ──────────────────────────────────────────────────────────
variable "gateway_url" {
  type        = string
  default     = null
  description = "OpenAI-compatible base URL of the LiteLLM gateway, e.g. http://litellm.internal:4000/v1. Required when llm_backend = \"gateway\"."
}

variable "gateway_security_group_id" {
  type        = string
  default     = null
  description = "If set, an ingress rule is added to the gateway's security group allowing the Lambdas."
}

variable "gateway_port" {
  type    = number
  default = 4000
}

variable "chat_model" {
  type    = string
  default = "audit-chat"
}

variable "batch_model" {
  type    = string
  default = "audit-batch"
}

variable "chat_temperature" {
  type        = string
  default     = "none"
  description = "\"none\" sends no temperature: Claude 5.x models reject any non-default value with a 400. Set e.g. \"0.2\" only for models that accept it."
}

variable "batch_temperature" {
  type        = string
  default     = "none"
  description = "As chat_temperature. \"0\" improves week-to-week consistency on models that accept a temperature."
}

# ── Database ─────────────────────────────────────────────────────────────────
variable "db_instance_class" {
  type    = string
  default = "db.t3.small"
}

variable "db_engine_version" {
  type    = string
  default = "16"
}

variable "db_allocated_storage" {
  type    = number
  default = 20
}

variable "db_multi_az" {
  type        = bool
  default     = false
  description = "Single-AZ is acceptable: raw collector output in S3 lets the data be rebuilt."
}

variable "db_deletion_protection" {
  type    = bool
  default = true
}

variable "db_backup_retention_days" {
  type        = number
  default     = 7
  description = "Automated backup retention. Free-plan accounts reject more than the free-tier maximum: use 1."
}

variable "db_skip_final_snapshot" {
  type        = bool
  default     = false
  description = "true for throwaway environments, so repeated destroy/apply cycles don't collide on the snapshot name."
}

# ── Identity ─────────────────────────────────────────────────────────────────
variable "entra_tenant_id" {
  type = string
}

variable "entra_client_id" {
  type        = string
  description = "Application (client) ID of the Entra app registration. Set accessTokenAcceptedVersion = 2 so tokens' audience is this id."
}

variable "entra_api_scope" {
  type        = string
  default     = null
  description = "Scope the web app requests. Defaults to api://<client id>/access_as_user."
}

variable "allowed_cidrs" {
  type        = list(string)
  default     = []
  description = "Office/VPN egress CIDRs. If non-empty, a WAF web ACL blocks every other source."
}

# ── GitHub App ───────────────────────────────────────────────────────────────
variable "github_org" {
  type        = string
  default     = "forbesadvisor"
  description = "Owner of the repos: an organization, or your personal account name (with github_owner_type = \"user\")."
}

variable "github_owner_type" {
  type    = string
  default = "org"
  validation {
    condition     = contains(["org", "user"], var.github_owner_type)
    error_message = "github_owner_type is \"org\" or \"user\"."
  }
}

variable "ownership_config" {
  type        = string
  default     = "ownership.yml"
  description = "Bundled ownership file in src/audit_agent/data, e.g. ownership.demo.yml for a personal account."
}

variable "team_group_ids" {
  type        = map(string)
  default     = {}
  description = "Entra group object id per team id, e.g. { web = \"<group object id>\" }. Overrides entra_group_id in the ownership file."
}

variable "github_app_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]+$", var.github_app_id))
    error_message = "github_app_id must be the numeric GitHub App ID (App settings page, e.g. 5594367), not a placeholder."
  }
}

variable "github_installation_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]+$", var.github_installation_id))
    error_message = "github_installation_id must be the numeric GitHub installation ID (the number in github.com/settings/installations/<id>), not a placeholder."
  }
}

# ── Weekly run ───────────────────────────────────────────────────────────────
variable "schedule_expression" {
  type    = string
  default = "cron(0 0 ? * MON *)"
}

variable "schedule_timezone" {
  type    = string
  default = "UTC"
}

variable "collectors" {
  type    = list(string)
  default = ["ownership", "dependabot", "guardduty"]
  validation {
    condition     = contains(var.collectors, "ownership")
    error_message = "The ownership collector must run; other findings get their team from it."
  }
  validation {
    condition     = alltrue([for c in var.collectors : contains(["ownership", "dependabot", "guardduty", "securityhub"], c)])
    error_message = "Collectors: ownership, dependabot, guardduty, securityhub."
  }
}

variable "security_audit_role_arn" {
  type        = string
  default     = null
  description = "Role in the security account that the GuardDuty collector assumes. Null = read GuardDuty in this account."
}

variable "guardduty_regions" {
  type    = list(string)
  default = ["us-east-1", "us-west-2", "ap-southeast-2", "ca-central-1", "eu-south-1", "eu-north-1", "eu-west-2"]
}

variable "investigate_max_concurrency" {
  type    = number
  default = 5
}

variable "max_investigations_per_run" {
  type    = number
  default = 100
}

# ── Lambda ───────────────────────────────────────────────────────────────────
variable "lambda_python_version" {
  type    = string
  default = "3.12"
}

variable "lambda_architecture" {
  type    = string
  default = "x86_64"
  validation {
    condition     = contains(["x86_64", "arm64"], var.lambda_architecture)
    error_message = "Use x86_64 or arm64."
  }
}

variable "chat_reserved_concurrency" {
  type        = number
  default     = 10
  description = "Caps database connections from chat. -1 = unreserved (needed in accounts with a low concurrency limit)."
}

# ── Operations ───────────────────────────────────────────────────────────────
variable "log_retention_days" {
  type    = number
  default = 30
}

variable "raw_retention_days" {
  type    = number
  default = 365
}

variable "alarm_email" {
  type        = string
  default     = null
  description = "Optional email subscribed to the alarm topic."
}

variable "secret_recovery_days" {
  type        = number
  default     = 7
  description = "0 deletes secrets immediately on destroy (throwaway environments), so the names can be reused at once."
}

variable "force_destroy_buckets" {
  type        = bool
  default     = false
  description = "true lets terraform destroy empty and delete the S3 buckets (throwaway environments only)."
}

variable "monthly_budget_usd" {
  type        = number
  default     = null
  description = "If set (and alarm_email is set), an AWS Budget emails at 50/80/100% of actual and 100% of forecast spend."
}

# ── Agent quality gates ──────────────────────────────────────────────────────
variable "confidence_threshold" {
  type        = number
  default     = 0.7
  description = "Answers and investigations below this confidence (0-1) loop back for more evidence, up to max_confidence_retries times, then are flagged (chat) or sent to a lead for review (investigations)."
  validation {
    condition     = var.confidence_threshold >= 0 && var.confidence_threshold <= 1
    error_message = "Use a value between 0 and 1."
  }
}

variable "max_confidence_retries" {
  type    = number
  default = 2
  validation {
    condition     = var.max_confidence_retries >= 0 && var.max_confidence_retries <= 5
    error_message = "Use 0 to 5."
  }
}

variable "verify_answers" {
  type        = bool
  default     = true
  description = "Score each chat answer against the evidence with a second model call (the confidence gate). Costs one extra call per answer."
}

variable "review_gate_timeout_hours" {
  type        = number
  default     = 72
  description = "How long the weekly run waits for a lead to review low-confidence investigations before sending the summary anyway."
}

# ── AgentCore (Runtime, Memory, Gateway, Policy) ─────────────────────────────
variable "agentcore_enabled" {
  type        = bool
  default     = true
  description = "false keeps the all-Lambda design: no AgentCore Runtime, Memory, Gateway or Policy (tools run in-process, memory in Postgres)."
}

variable "agentcore_runtime_python" {
  type        = string
  default     = "3.12"
  description = "Python version for AgentCore Runtime code deployments (arm64)."
  validation {
    condition     = contains(["3.10", "3.11", "3.12", "3.13"], var.agentcore_runtime_python)
    error_message = "Use 3.10 to 3.13."
  }
}

variable "agentcore_tracing" {
  type        = bool
  default     = false
  description = "OpenTelemetry tracing for the Runtime agents (AgentCore Observability). Needs CloudWatch Transaction Search turned on once per account (see local/DEPLOY-DEMO.md)."
}

variable "agentcore_memory_long_term" {
  type        = bool
  default     = false
  description = "Add long-term memory strategies (user preferences, session summaries). They are extracted by an AgentCore-managed model; leave off if your account can't use it."
}

variable "memory_event_expiry_days" {
  type    = number
  default = 30
  validation {
    condition     = var.memory_event_expiry_days >= 7 && var.memory_event_expiry_days <= 365
    error_message = "AgentCore Memory keeps events 7 to 365 days."
  }
}

variable "agentcore_policy_mode" {
  type        = string
  default     = "ENFORCE"
  description = "ENFORCE: Cedar policies decide every Gateway tool call. LOG_ONLY: decisions are logged, not enforced (for rollout)."
  validation {
    condition     = contains(["ENFORCE", "LOG_ONLY"], var.agentcore_policy_mode)
    error_message = "Use ENFORCE or LOG_ONLY."
  }
}

variable "scope_key_version" {
  type        = number
  default     = 1
  description = "Bump to rotate the key that signs scope tokens between the agents and Gateway tools."
}

# ── Fix agent (LangGraph on AgentCore Runtime, A2A) ──────────────────────────
variable "fix_agent_enabled" {
  type    = bool
  default = true
}

variable "fix_github_app_id" {
  type        = string
  default     = null
  description = "A SECOND GitHub App with Contents and Pull requests: write, used only to open approved fix PRs. Unset = fixes can be drafted and approved, but opening the PR fails with a clear error."
  validation {
    condition     = var.fix_github_app_id == null || can(regex("^[0-9]+$", var.fix_github_app_id))
    error_message = "The App ID is a number (App settings > General > App ID)."
  }
}

variable "fix_github_installation_id" {
  type    = string
  default = null
  validation {
    condition     = var.fix_github_installation_id == null || can(regex("^[0-9]+$", var.fix_github_installation_id))
    error_message = "The installation ID is the number at the end of the installation's settings URL."
  }
}

# ── Server diagnostics (SSM Run Command, read-only checks) ───────────────────
variable "diagnostics_enabled" {
  type    = bool
  default = false
}

variable "diagnostic_services" {
  type        = list(string)
  default     = ["amazon-ssm-agent", "sshd", "nginx", "crond"]
  description = "systemd units the service_status check may inspect."
  validation {
    condition     = alltrue([for s in var.diagnostic_services : can(regex("^[A-Za-z0-9_.@-]{1,64}$", s))])
    error_message = "Unit names: letters, digits and _ . @ - only."
  }
}

variable "diagnostic_logs" {
  type        = map(string)
  default     = { system = "journal", nginx_error = "/var/log/nginx/error.log", cloud_init = "/var/log/cloud-init-output.log" }
  description = "Log names the recent_logs check may read, mapped to a file path (or \"journal\" for the systemd journal)."
  validation {
    condition = alltrue([for k, v in var.diagnostic_logs : can(regex("^[A-Za-z0-9_-]{1,32}$", k)) &&
    (v == "journal" || can(regex("^/var/log/[A-Za-z0-9_./-]+$", v)))])
    error_message = "Names: letters, digits, _ and -; paths must be under /var/log/ (or \"journal\")."
  }
}

variable "diagnostics_demo_instance" {
  type        = bool
  default     = false
  description = "Create one small instance (tagged for diagnostics) in a private subnet to try the checks on."
}

variable "diagnostics_demo_instance_type" {
  type        = string
  default     = "t4g.micro"
  description = "Graviton (arm64). Free-plan accounts allow only free-tier-eligible types."
}

variable "diagnostics_demo_team" {
  type        = string
  default     = null
  description = "Team id that owns the demo instance (its `team` tag). Required with diagnostics_demo_instance."
}

# ── AWS read tools for chat (CloudWatch Logs Insights, AWS Config) ───────────
variable "aws_logs_tool_enabled" {
  type        = bool
  default     = false
  description = "Chat can search CloudWatch log groups tagged team=<team id> (fixed query templates, read-only)."
}

variable "logs_tool_max_hours" {
  type        = number
  default     = 24
  description = "Longest time window a log query may cover (bounds the data each query scans, and its cost)."
  validation {
    condition     = var.logs_tool_max_hours >= 1 && var.logs_tool_max_hours <= 168
    error_message = "Use 1 to 168 hours."
  }
}

variable "aws_config_tool_enabled" {
  type        = bool
  default     = false
  description = "Chat can list AWS resources tagged team=<team id>, read their AWS Config record and failing Config rules."
}

variable "enable_config_recorder" {
  type        = bool
  default     = false
  description = "Create an AWS Config recorder (S3 buckets, EC2 instances, security groups only) and three managed rules. Leave false if the account already has a recorder in this region (one per region)."
}

# ── Security Hub ────────────────────────────────────────────────────────────
variable "enable_securityhub" {
  type        = bool
  default     = false
  description = "Turn on Security Hub with the AWS Foundational Security Best Practices standard (most controls need an AWS Config recorder). Add \"securityhub\" to collectors to report its findings."
}

variable "securityhub_regions" {
  type        = list(string)
  default     = []
  description = "Regions the securityhub collector reads. Empty = the deployment region."
}

# ── Demo AWS resources for the AWS tools ────────────────────────────────────
variable "demo_aws_resources" {
  type        = bool
  default     = false
  description = "Create a log group /demo/storefront (team web) with sample log lines, and an S3 bucket (team data) without versioning, so the logs and Config tools have something to find."
}

# ── Terraform drafter ─────────────────────────────────────────────────────────────────
variable "infra_drafter_enabled" {
  type        = bool
  default     = false
  description = "Team members describe infrastructure in the web app; the fix runtime drafts Terraform for a lead to approve and opens a PR on infra_repo. Needs agentcore_enabled and fix_agent_enabled, and the fix-bot GitHub App installed on infra_repo with contents and pull-request write."
}

variable "infra_repo" {
  type        = string
  default     = "demo-infra-terraform"
  description = "The shared Terraform repo (in github_org) the drafter reads and opens PRs on. Drafts only ever touch teams/<team>/."
}

variable "infra_model" {
  type        = string
  default     = null
  description = "Model for the drafter; null = chat_model."
}
