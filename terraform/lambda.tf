# Seven functions from one code package (plus the Gateway tools Lambda in agentcore.tf). Every deploy publishes a version and moves the
# `live` alias; Step Functions, the function URL and Terraform's migration call all use the
# alias, so rolling back is: aws lambda update-alias --name live --function-version <previous>.

locals {
  db_env = {
    DB_HOST = aws_db_instance.db.address
    DB_PORT = tostring(aws_db_instance.db.port)
    DB_NAME = aws_db_instance.db.db_name
  }
  github_env = {
    GITHUB_ORG                = var.github_org
    GITHUB_OWNER_TYPE         = var.github_owner_type
    GITHUB_APP_ID             = var.github_app_id
    GITHUB_INSTALLATION_ID    = var.github_installation_id
    GITHUB_PRIVATE_KEY_SECRET = aws_secretsmanager_secret.github_private_key.arn
  }
  agent_env = merge(local.db_env, local.github_env, {
    DB_USER             = local.app_db_user
    LLM_BACKEND         = var.llm_backend
    GATEWAY_URL         = coalesce(var.gateway_url, "unused")
    GATEWAY_KEYS_SECRET = aws_secretsmanager_secret.gateway_keys.arn
    CHAT_MODEL          = var.chat_model
    BATCH_MODEL         = var.batch_model
    CHAT_TEMPERATURE    = var.chat_temperature
    BATCH_TEMPERATURE   = var.batch_temperature
    ENTRA_TENANT_ID     = var.entra_tenant_id
    ENTRA_AUDIENCE      = var.entra_client_id
    # A user is waiting (chat 55 s timeout): don't sit out a long GitHub rate-limit reset.
    GITHUB_MAX_RATE_WAIT_S = "15"
    CONFIDENCE_THRESHOLD   = tostring(var.confidence_threshold)
    MAX_CONFIDENCE_RETRIES = tostring(var.max_confidence_retries)
    VERIFY_ANSWERS         = tostring(var.verify_answers)
  })

  # With AgentCore on, chat forwards questions to the Runtime agent and releases review gates.
  chat_agentcore_env = merge(local.agentcore_env, { for k, v in {
    AGENT_RUNTIME_URL = local.runtime_url.audit
    STATE_MACHINE_ARN = local.state_machine_arn
  } : k => v if v != null })
  # Investigations use the Gateway tools but not memory, the fix agent or diagnostics.
  investigate_agentcore_env = { for k, v in local.agentcore_env : k => v
  if contains(["GATEWAY_MCP_URL", "GATEWAY_TOOLS", "SCOPE_KEY_SECRET"], k) }

  # Unset = the GuardDuty collector reads this account. The variable is left out entirely
  # when there is no role (coalesce() can't return "", and `cond ? {} : {...}` is a type error).
  collect_role_env = { for k, v in { SECURITY_AUDIT_ROLE_ARN = var.security_audit_role_arn } : k => v if v != null }

  functions = tomap({
    chat = {
      handler  = "audit_agent.handlers.chat.handler"
      timeout  = 55 # stays under CloudFront's 60 s origin read timeout
      memory   = 512
      in_vpc   = true
      reserved = var.chat_reserved_concurrency
      # CHAT_ASYNC: answers run as background jobs so the page can show progress steps
      env = tomap(merge(local.agent_env, local.chat_agentcore_env, { CHAT_ASYNC = "true" }))
    }
    investigate = {
      handler  = "audit_agent.handlers.investigate.handler"
      timeout  = 180
      memory   = 512
      in_vpc   = true
      reserved = -1
      env      = tomap(merge(local.agent_env, local.investigate_agentcore_env))
    }
    ingest = {
      handler  = "audit_agent.handlers.ingest.handler"
      timeout  = 300
      memory   = 1024
      in_vpc   = true
      reserved = -1
      env = tomap(merge(local.db_env, {
        DB_USER            = local.ingest_db_user
        DATA_BUCKET        = aws_s3_bucket.data.bucket
        MAX_INVESTIGATIONS = tostring(var.max_investigations_per_run)
      }))
    }
    collect = {
      handler  = "audit_agent.handlers.collect.handler"
      timeout  = 900
      memory   = 1024
      in_vpc   = false # only calls GitHub/AWS APIs and writes to S3
      reserved = -1
      env = tomap(merge(local.github_env, local.collect_role_env, {
        DATA_BUCKET            = aws_s3_bucket.data.bucket
        OWNERSHIP_CONFIG       = var.ownership_config
        TEAM_GROUP_IDS         = jsonencode(var.team_group_ids)
        GUARDDUTY_REGIONS      = join(",", var.guardduty_regions)
        GITHUB_MAX_RATE_WAIT_S = "300" # batch job with a 900 s timeout can afford to wait
      }))
    }
    notify = {
      handler  = "audit_agent.handlers.notify.handler"
      timeout  = 30
      memory   = 256
      in_vpc   = false
      reserved = -1
      env      = tomap({ SLACK_WEBHOOK_SECRET = aws_secretsmanager_secret.slack_webhook.arn })
    }
    review_gate = {
      handler  = "audit_agent.handlers.review_gate.handler"
      timeout  = 30
      memory   = 256
      in_vpc   = true
      reserved = -1
      env = tomap(merge(local.db_env, {
        DB_USER              = local.ingest_db_user # counts pending reviews across all teams
        SLACK_WEBHOOK_SECRET = aws_secretsmanager_secret.slack_webhook.arn
      }))
    }
    migrate = {
      handler  = "audit_agent.handlers.migrate.handler"
      timeout  = 120
      memory   = 256
      in_vpc   = true
      reserved = -1
      env = tomap(merge(local.db_env, {
        DB_MASTER_SECRET_ARN = aws_db_instance.db.master_user_secret[0].secret_arn
      }))
    }
  })
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each          = local.functions
  name              = "/aws/lambda/${local.name}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "fn" {
  for_each = local.functions

  function_name    = "${local.name}-${each.key}"
  role             = aws_iam_role.fn[each.key].arn
  runtime          = "python${var.lambda_python_version}"
  architectures    = [var.lambda_architecture]
  handler          = each.value.handler
  filename         = data.archive_file.code.output_path
  source_code_hash = data.archive_file.code.output_base64sha256
  layers           = [aws_lambda_layer_version.deps.arn]
  timeout          = each.value.timeout
  memory_size      = each.value.memory
  publish          = true

  reserved_concurrent_executions = each.value.reserved

  environment {
    variables = each.value.env
  }

  dynamic "vpc_config" {
    for_each = each.value.in_vpc ? [1] : []
    content {
      subnet_ids         = local.private_subnet_ids
      security_group_ids = [aws_security_group.lambda.id]
    }
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy_attachment.fn_base]
}

resource "aws_lambda_alias" "live" {
  for_each         = aws_lambda_function.fn
  name             = "live"
  function_name    = each.value.function_name
  function_version = each.value.version
}

# Apply the schema on create and whenever schema.sql changes. A failure fails the apply.
resource "aws_lambda_invocation" "migrate" {
  function_name = aws_lambda_function.fn["migrate"].function_name
  qualifier     = aws_lambda_alias.live["migrate"].name
  input         = jsonencode({ schema_sha256 = filesha256("${local.src_dir}/audit_agent/sql/schema.sql") })

  depends_on = [
    aws_vpc_security_group_ingress_rule.db_from_lambda,
    aws_route.private_via_instance, # create_vpc only: Secrets Manager is reached via the NAT
    aws_route.private_via_gateway,
  ]
}

# Background chat jobs are this function invoking itself asynchronously. A failed job is
# reported to the user as an error; retrying it would answer the same question twice.
resource "aws_lambda_function_event_invoke_config" "chat" {
  function_name                = aws_lambda_function.fn["chat"].function_name
  qualifier                    = aws_lambda_alias.live["chat"].name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 60
}
