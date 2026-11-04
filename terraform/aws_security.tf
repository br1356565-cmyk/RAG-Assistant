# Optional AWS security data for the agents:
#   * an AWS Config recorder (a few resource types) and three managed rules, read by the
#     Config chat tools and by Security Hub's controls;
#   * Security Hub with the AWS Foundational Security Best Practices standard, reported by
#     the "securityhub" collector;
#   * demo resources the AWS tools can find: a team-web log group with sample lines and a
#     team-data bucket that fails the versioning rule.
# All off by default: Config and Security Hub are billed per recorded change / check.

locals {
  config_on = var.enable_config_recorder
}

# ── AWS Config recorder ─────────────────────────────────────────────────────
resource "aws_iam_role" "config" {
  count = local.config_on ? 1 : 0
  name  = "${local.name}-config"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "config.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = local.config_on ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket_policy" "config_delivery" {
  count  = local.config_on ? 1 : 0
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid    = "ConfigAclCheck", Effect = "Allow", Principal = { Service = "config.amazonaws.com" },
        Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.data.arn,
      Condition = { StringEquals = { "AWS:SourceAccount" = local.account_id } } },
      { Sid       = "ConfigWrite", Effect = "Allow", Principal = { Service = "config.amazonaws.com" },
        Action    = "s3:PutObject", Resource = "${aws_s3_bucket.data.arn}/config/AWSLogs/${local.account_id}/Config/*",
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control", "AWS:SourceAccount" = local.account_id } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.data]
}

resource "aws_config_configuration_recorder" "this" {
  count    = local.config_on ? 1 : 0
  name     = "${local.name}-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::S3::Bucket", "AWS::EC2::Instance", "AWS::EC2::SecurityGroup"]
    recording_strategy {
      use_only = "INCLUSION_BY_RESOURCE_TYPES"
    }
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = local.config_on ? 1 : 0
  name           = "${local.name}-delivery"
  s3_bucket_name = aws_s3_bucket.data.bucket
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.config_delivery]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = local.config_on ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_config_rule" "managed" {
  for_each = { for k, v in {
    s3-bucket-versioning-enabled     = { id = "S3_BUCKET_VERSIONING_ENABLED", types = ["AWS::S3::Bucket"] }
    s3-bucket-public-read-prohibited = { id = "S3_BUCKET_PUBLIC_READ_PROHIBITED", types = ["AWS::S3::Bucket"] }
    restricted-ssh                   = { id = "INCOMING_SSH_DISABLED", types = ["AWS::EC2::SecurityGroup"] }
  } : k => v if local.config_on }
  name = each.key
  source {
    owner             = "AWS"
    source_identifier = each.value.id
  }
  scope {
    compliance_resource_types = each.value.types
  }
  depends_on = [aws_config_configuration_recorder_status.this]
}

# ── Security Hub ─────────────────────────────────────────────────────────────
resource "aws_securityhub_account" "this" {
  count                    = var.enable_securityhub ? 1 : 0
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# ── Demo resources for the AWS tools ────────────────────────────────────────
resource "aws_cloudwatch_log_group" "demo_storefront" {
  count             = var.demo_aws_resources ? 1 : 0
  name              = "/demo/storefront"
  retention_in_days = 7
  tags              = { team = "web" }
}

# Sample lines, written once when the group is created; re-run local/seed_demo_logs.sh to
# refresh them (queries only look back logs_tool_max_hours).
resource "terraform_data" "demo_logs" {
  count            = var.demo_aws_resources ? 1 : 0
  triggers_replace = [aws_cloudwatch_log_group.demo_storefront[0].arn]

  provisioner "local-exec" {
    command = "bash ${local.repo_root}/local/seed_demo_logs.sh ${aws_cloudwatch_log_group.demo_storefront[0].name} ${var.aws_region}"
  }
}

resource "aws_s3_bucket" "demo_exports" {
  count         = var.demo_aws_resources ? 1 : 0
  bucket        = "${local.name}-exports-${local.account_id}"
  force_destroy = true
  tags          = { team = "data" } # no versioning: fails s3-bucket-versioning-enabled
}

resource "aws_s3_bucket_public_access_block" "demo_exports" {
  count                   = var.demo_aws_resources ? 1 : 0
  bucket                  = aws_s3_bucket.demo_exports[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
