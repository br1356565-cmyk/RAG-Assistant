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
    gateway_keys       = local.litellm ? "filled automatically by the LiteLLM key bootstrap" : "${aws_secretsmanager_secret.gateway_keys.arn}  JSON: {\"default\": \"sk-...\", \"<team_id>\": \"sk-...\"}"
    github_private_key = "${aws_secretsmanager_secret.github_private_key.arn}  PEM file of the GitHub App"
    slack_webhook      = "${aws_secretsmanager_secret.slack_webhook.arn}  https://hooks.slack.com/services/..."
    fix_github_key     = local.agentcore && var.fix_agent_enabled ? "${aws_secretsmanager_secret.fix_github_private_key[0].arn}  PEM file of the fix-bot GitHub App (write access)" : "not used"
    jira               = var.jira_enabled ? "${aws_secretsmanager_secret.jira[0].arn}  JSON: {\"base_url\": \"https://<site>.atlassian.net\", \"email\": \"...\", \"api_token\": \"...\"}" : "not used"
  }
}

output "litellm" {
  description = "The LiteLLM proxy (null when litellm_enabled = false). Keys: the gateway_keys secret."
  value = local.litellm ? {
    url          = local.llm_gateway_url
    log_group    = aws_cloudwatch_log_group.litellm[0].name
    guardrails   = { pii = aws_bedrock_guardrail.pii[0].guardrail_id, policy = aws_bedrock_guardrail.policy[0].guardrail_id }
    key_names    = local.llm_key_names
    keys_created = try(jsondecode(aws_lambda_invocation.llm_keys[0].result), null)
  } : null
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

output "scanning" {
  description = "Org-wide SAST/DAST scan tasks and team reports"
  value = {
    sast          = var.sast_enabled ? "${aws_ecs_task_definition.scan["sast"].family} (logs: /ecs/${local.name}-sast)" : "off"
    dast          = var.dast_enabled ? "${aws_ecs_task_definition.scan["dast"].family} (logs: /ecs/${local.name}-dast)" : "off"
    collectors    = local.run_collectors
    digest_sender = coalesce(var.digest_sender, "off (set digest_sender)")
    dashboard_url = local.dashboard_url
  }
}
