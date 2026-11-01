# Terraform creates the secret containers only. Values are set out of band so they never
# land in Terraform state:
#   aws secretsmanager put-secret-value --secret-id <arn> --secret-string file://value
# The outputs list each ARN and the expected format.

resource "aws_secretsmanager_secret" "gateway_keys" {
  name                    = "${local.name}/gateway-keys"
  description             = "LiteLLM virtual keys as JSON: {\"default\": \"sk-...\", \"<team_id>\": \"sk-...\"}"
  recovery_window_in_days = var.secret_recovery_days
}

resource "aws_secretsmanager_secret" "github_private_key" {
  name                    = "${local.name}/github-app-private-key"
  description             = "PEM private key of the GitHub App"
  recovery_window_in_days = var.secret_recovery_days
}

resource "aws_secretsmanager_secret" "slack_webhook" {
  name                    = "${local.name}/slack-webhook"
  description             = "Slack incoming webhook URL for weekly run summaries"
  recovery_window_in_days = var.secret_recovery_days
}
