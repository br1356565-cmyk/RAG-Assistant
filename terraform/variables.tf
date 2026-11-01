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
}

variable "github_installation_id" {
  type = string
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
