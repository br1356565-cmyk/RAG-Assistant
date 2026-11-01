data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name       = var.name_prefix
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  tags       = merge({ Project = "devops-audit-agent", ManagedBy = "terraform" }, var.tags)

  api_scope = coalesce(var.entra_api_scope, "api://${var.entra_client_id}/access_as_user")

  app_db_user    = "audit_app_login"
  ingest_db_user = "audit_ingest_login"
  db_user_arn    = "arn:${local.partition}:rds-db:${var.aws_region}:${local.account_id}:dbuser:${aws_db_instance.db.resource_id}"
}
