output "web_url" {
  value = "https://${aws_cloudfront_distribution.web.domain_name}/"
}

output "entra_redirect_uri" {
  description = "Register this as a Single-page application redirect URI on the Entra app registration."
  value       = "https://${aws_cloudfront_distribution.web.domain_name}/"
}

output "state_machine_arn" {
  value = aws_sfn_state_machine.weekly.arn
}

output "db_endpoint" {
  value = aws_db_instance.db.address
}

output "data_bucket" {
  value = aws_s3_bucket.data.bucket
}

output "lambda_security_group_id" {
  description = "Allow this security group on the LiteLLM gateway if gateway_security_group_id wasn't set."
  value       = aws_security_group.lambda.id
}

output "secrets_to_populate" {
  description = "Set these once with: aws secretsmanager put-secret-value --secret-id <arn> --secret-string file://<file>"
  value = {
    gateway_keys       = "${aws_secretsmanager_secret.gateway_keys.arn}  JSON: {\"default\": \"sk-...\", \"<team_id>\": \"sk-...\"}"
    github_private_key = "${aws_secretsmanager_secret.github_private_key.arn}  PEM file of the GitHub App"
    slack_webhook      = "${aws_secretsmanager_secret.slack_webhook.arn}  https://hooks.slack.com/services/..."
    fix_github_key     = local.agentcore && var.fix_agent_enabled ? "${aws_secretsmanager_secret.fix_github_private_key[0].arn}  PEM file of the fix-bot GitHub App (write access)" : "not used"
  }
}

output "collector_role_arn" {
  description = "If GuardDuty lives in a security account, that account's audit role must trust this role."
  value       = aws_iam_role.fn["collect"].arn
}

output "collectors" {
  description = "Collectors the weekly run uses (input for a manual run)."
  value       = var.collectors
}

output "agentcore" {
  description = "AgentCore pieces (null when agentcore_enabled = false)."
  value = local.agentcore ? {
    audit_runtime_arn = aws_bedrockagentcore_agent_runtime.audit[0].agent_runtime_arn
    fix_runtime_arn   = var.fix_agent_enabled ? aws_bedrockagentcore_agent_runtime.fix[0].agent_runtime_arn : null
    memory_id         = aws_bedrockagentcore_memory.chat[0].id
    gateway_url       = aws_bedrockagentcore_gateway.tools[0].gateway_url
    policy_engine_id  = aws_bedrockagentcore_policy_engine.tools[0].policy_engine_id
    policy_mode       = var.agentcore_policy_mode
    gateway_tools     = local.gateway_tools
  } : null
}

output "diagnostics_demo_instance_id" {
  value = var.diagnostics_enabled && var.diagnostics_demo_instance ? aws_instance.diag_demo[0].id : null
}

output "dashboard_url" {
  value = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.agent.dashboard_name}"
}
