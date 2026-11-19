# LiteLLM: every model call in the stack (chat, investigations, the verifier, the fix agent,
# the Terraform drafter) goes through one LiteLLM proxy with Amazon Bedrock Guardrails. Nothing
# here is manual: Terraform generates the master and salt keys and the database password into
# Secrets Manager (write-only, never in state), the migrate Lambda creates LiteLLM's database,
# and a bootstrap Lambda creates the virtual keys through LiteLLM's API and stores them in the
# gateway keys secret the agents read.
#
#   Lambdas / AgentCore runtimes (VPC) ─▶ http://litellm.<name>.internal:4000  (Cloud Map DNS)
#                                          └ ECS Fargate task, private subnets, no load balancer
#                                             ├ guardrails: PII masking (pre-call), policy block
#                                             └ Bedrock (task role) · RDS database "litellm"

locals {
  litellm      = var.litellm_enabled
  llm_backend  = local.litellm ? "gateway" : var.llm_backend
  litellm_host = "litellm.${local.name}.internal"
  litellm_url  = "http://${local.litellm_host}:4000"
  # The OpenAI-compatible base URL the agents use, and the model names they ask for.
  llm_gateway_url  = local.litellm ? "${local.litellm_url}/v1" : var.gateway_url
  chat_model_name  = local.litellm ? "audit-chat" : var.chat_model
  batch_model_name = local.litellm ? "audit-batch" : var.batch_model

  # Teams get their own key (cost per team in LiteLLM); so do the fix agent and the drafter.
  ownership_teams = [for t in try(yamldecode(file("${local.src_dir}/audit_agent/data/${var.ownership_config}")).teams, []) : t.id]
  llm_key_names   = distinct(concat(["default", "fix", "infra"], local.ownership_teams))
  llm_key_spec = jsonencode({
    prefix = local.name
    keys = { for n in local.llm_key_names : n => {
      models          = ["audit-chat", "audit-batch"]
      max_budget      = var.litellm_key_budget_usd
      budget_duration = "30d"
      rpm_limit       = var.litellm_key_rpm
    } }
  })

  litellm_config = yamlencode({
    model_list = [
      { model_name = "audit-chat", litellm_params = { model = "bedrock/converse/${var.chat_model}", aws_region_name = var.aws_region } },
      { model_name = "audit-batch", litellm_params = { model = "bedrock/converse/${var.batch_model}", aws_region_name = var.aws_region } },
    ]
    guardrails = [
      {
        # Masks secrets and contact details before the model sees them (tool results included:
        # repo files and logs are where leaked keys turn up).
        guardrail_name = "pii-mask"
        litellm_params = {
          guardrail             = "bedrock"
          mode                  = "pre_call"
          guardrailIdentifier   = try(aws_bedrock_guardrail.pii[0].guardrail_id, null)
          guardrailVersion      = try(aws_bedrock_guardrail_version.pii[0].version, null)
          aws_region_name       = var.aws_region
          mask_request_content  = true
          mask_response_content = true
          default_on            = true
        }
      },
      {
        # Blocks harmful content and prompt attacks in what users type. Tool results are
        # skipped: repo text is untrusted data the harness already labels, and a planted
        # injection string should be ignored by the agent, not fail the whole request.
        guardrail_name = "policy-block"
        litellm_params = {
          guardrail                      = "bedrock"
          mode                           = "pre_call"
          guardrailIdentifier            = try(aws_bedrock_guardrail.policy[0].guardrail_id, null)
          guardrailVersion               = try(aws_bedrock_guardrail_version.policy[0].version, null)
          aws_region_name                = var.aws_region
          default_on                     = true
          skip_tool_message_in_guardrail = true
        }
      },
    ]
    litellm_settings = {
      drop_params     = true # Nova rejects some OpenAI parameters; drop them instead of failing
      request_timeout = 120
      num_retries     = 2
    }
    general_settings = {
      master_key   = "os.environ/LITELLM_MASTER_KEY"
      database_url = "os.environ/DATABASE_URL"
    }
  })
}

# ── Guardrails ───────────────────────────────────────────────────────────────────────────
resource "aws_bedrock_guardrail" "pii" {
  count                     = local.litellm ? 1 : 0
  name                      = "${local.name}-pii"
  description               = "Masks credentials and contact details in prompts and answers"
  blocked_input_messaging   = "This request contained sensitive data that can't be sent to the model."
  blocked_outputs_messaging = "The answer contained sensitive data and was withheld."

  sensitive_information_policy_config {
    dynamic "pii_entities_config" {
      for_each = ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD", "EMAIL", "PHONE"]
      content {
        type   = pii_entities_config.value
        action = "ANONYMIZE"
      }
    }
    regexes_config {
      name        = "github-token"
      description = "GitHub personal access and app tokens"
      pattern     = "gh[pousr]_[A-Za-z0-9]{36,}"
      action      = "ANONYMIZE"
    }
    regexes_config {
      name        = "private-key"
      description = "PEM private key headers"
      pattern     = "-----BEGIN [A-Z ]*PRIVATE KEY-----"
      action      = "ANONYMIZE"
    }
  }
}

resource "aws_bedrock_guardrail_version" "pii" {
  count         = local.litellm ? 1 : 0
  guardrail_arn = aws_bedrock_guardrail.pii[0].guardrail_arn
  description   = "managed by terraform"
  # a new version whenever the guardrail's configuration changes
  lifecycle {
    replace_triggered_by = [aws_bedrock_guardrail.pii[0]]
  }
}

resource "aws_bedrock_guardrail" "policy" {
  count                     = local.litellm ? 1 : 0
  name                      = "${local.name}-policy"
  description               = "Blocks harmful content and prompt attacks"
  blocked_input_messaging   = "This request was blocked by the content policy."
  blocked_outputs_messaging = "The answer was blocked by the content policy."

  content_policy_config {
    dynamic "filters_config" {
      for_each = ["HATE", "INSULTS", "SEXUAL", "VIOLENCE", "MISCONDUCT"]
      content {
        type            = filters_config.value
        input_strength  = "HIGH"
        output_strength = "HIGH"
      }
    }
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE" # prompt attacks are an input-only filter
    }
  }
}

resource "aws_bedrock_guardrail_version" "policy" {
  count         = local.litellm ? 1 : 0
  guardrail_arn = aws_bedrock_guardrail.policy[0].guardrail_arn
  description   = "managed by terraform"
  lifecycle {
    replace_triggered_by = [aws_bedrock_guardrail.policy[0]]
  }
}

# ── Secrets (generated here, written write-only: never in Terraform state) ───────────────
resource "aws_secretsmanager_secret" "litellm" {
  count                   = local.litellm ? 1 : 0
  name                    = "${local.name}/litellm"
  description             = "LiteLLM master key, salt key and database login (managed by Terraform)"
  recovery_window_in_days = var.secret_recovery_days
}

ephemeral "random_password" "litellm_master" {
  count   = local.litellm ? 1 : 0
  length  = 40
  special = false
}

ephemeral "random_password" "litellm_salt" {
  count   = local.litellm ? 1 : 0
  length  = 40
  special = false
}

ephemeral "random_password" "litellm_db" {
  count   = local.litellm ? 1 : 0
  length  = 32
  special = false
}

# Written once per litellm_secret_version. Don't bump it casually: the salt key encrypts
# what LiteLLM stores, and a new master key invalidates nothing but must reach the bootstrap.
resource "aws_secretsmanager_secret_version" "litellm" {
  count     = local.litellm ? 1 : 0
  secret_id = aws_secretsmanager_secret.litellm[0].id
  secret_string_wo = jsonencode({
    master_key   = "sk-${ephemeral.random_password.litellm_master[0].result}"
    salt_key     = "sk-${ephemeral.random_password.litellm_salt[0].result}"
    db_user      = "litellm"
    db_name      = "litellm"
    db_password  = ephemeral.random_password.litellm_db[0].result
    database_url = "postgresql://litellm:${ephemeral.random_password.litellm_db[0].result}@${aws_db_instance.db.address}:${aws_db_instance.db.port}/litellm?sslmode=require"
  })
  secret_string_wo_version = var.litellm_secret_version
}

# ── Network: private only ────────────────────────────────────────────────────────────────
resource "aws_security_group" "litellm" {
  count       = local.litellm ? 1 : 0
  name        = "${local.name}-litellm"
description = "LiteLLM proxy - reachable only from the stack Lambdas and AgentCore runtimes"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "litellm_from_lambda" {
  count                        = local.litellm ? 1 : 0
  security_group_id            = aws_security_group.litellm[0].id
  referenced_security_group_id = aws_security_group.lambda.id
  ip_protocol                  = "tcp"
  from_port                    = 4000
  to_port                      = 4000
  description                  = "Agents and the key bootstrap"
}

resource "aws_vpc_security_group_egress_rule" "litellm_all" {
  count             = local.litellm ? 1 : 0
  security_group_id = aws_security_group.litellm[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Bedrock, Secrets Manager, the image registry (via NAT) and RDS"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_litellm" {
  count                        = local.litellm ? 1 : 0
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.litellm[0].id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description = "LiteLLM database"
}

resource "aws_service_discovery_private_dns_namespace" "internal" {
  count       = local.litellm ? 1 : 0
  name        = "${local.name}.internal"
  description = "Private names for services inside the VPC"
  vpc         = local.vpc_id
}

resource "aws_service_discovery_service" "litellm" {
  count = local.litellm ? 1 : 0
  name  = "litellm"
  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.internal[0].id
    routing_policy = "MULTIVALUE"
    dns_records {
      type = "A"
      ttl  = 10
    }
  }
}

# ── IAM ──────────────────────────────────────────────────────────────────────────────────
data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "litellm_exec" {
  count              = local.litellm ? 1 : 0
  name               = "${local.name}-litellm-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "litellm_exec" {
  count      = local.litellm ? 1 : 0
  role       = aws_iam_role.litellm_exec[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "litellm_exec_secrets" {
  count = local.litellm ? 1 : 0
  name  = "secrets"
  role  = aws_iam_role.litellm_exec[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.litellm[0].arn]
  }] })
}

resource "aws_iam_role" "litellm_task" {
  count              = local.litellm ? 1 : 0
  name               = "${local.name}-litellm-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

# The proxy is the only thing in the stack that calls Bedrock.
resource "aws_iam_role_policy" "litellm_task" {
  count = local.litellm ? 1 : 0
  name  = "bedrock"
  role  = aws_iam_role.litellm_task[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], Resource = [
      "arn:${local.partition}:bedrock:*::foundation-model/*",
      "arn:${local.partition}:bedrock:*:${local.account_id}:inference-profile/*",
    ] },
    { Effect = "Allow", Action = ["bedrock:ApplyGuardrail"], Resource = [
      aws_bedrock_guardrail.pii[0].guardrail_arn, aws_bedrock_guardrail.policy[0].guardrail_arn,
    ] },
    # ECS Exec (the SSM agent in the task opens its channel through these)
    { Effect = "Allow", Action = [
      "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel",
    ], Resource = "*" },
  ] })
}

# ── The service ──────────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "litellm" {
  count             = local.litellm ? 1 : 0
  name              = "/ecs/${local.name}-litellm"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "llm" {
  count = local.litellm ? 1 : 0
  name  = "${local.name}-llm"
}

resource "aws_ecs_task_definition" "litellm" {
  count                    = local.litellm ? 1 : 0
  family                   = "${local.name}-litellm"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.litellm_cpu
  memory                   = var.litellm_memory
  execution_role_arn       = aws_iam_role.litellm_exec[0].arn
  task_role_arn            = aws_iam_role.litellm_task[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.litellm_cpu_architecture
  }

  container_definitions = jsonencode([{
    name      = "litellm"
    image     = var.litellm_image
    essential = true
    # The config comes from Terraform (an environment variable written to a file at start), so a
    # config change is a new task definition revision and a rolling restart: no image to build.
    entryPoint   = ["/bin/sh", "-c"]
    command      = ["printf '%s' \"$LITELLM_CONFIG_YAML\" > /tmp/litellm.yaml && exec litellm --config /tmp/litellm.yaml --port 4000 --num_workers 1"]
    portMappings = [{ containerPort = 4000, protocol = "tcp" }]
    # /health/liveliness needs no key. Python is always in the image (curl/wget may not be).
    # startPeriod covers LiteLLM's database migration on boot; failures in it don't count.
    healthCheck = {
      command     = ["CMD-SHELL", "$(command -v python3 || command -v python) -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=4)\" || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 180
    }
    environment = [
      { name = "LITELLM_CONFIG_YAML", value = local.litellm_config },
      { name = "AWS_REGION", value = var.aws_region },
      { name = "AWS_DEFAULT_REGION", value = var.aws_region },
      { name = "LITELLM_LOG", value = "INFO" },
      { name = "PYTHONUNBUFFERED", value = "1" }, # flush startup output so a crash still leaves logs
      { name = "DISABLE_ADMIN_UI", value = "True" },
      { name = "STORE_MODEL_IN_DB", value = "False" },
    ]
    secrets = [
      { name = "LITELLM_MASTER_KEY", valueFrom = "${aws_secretsmanager_secret.litellm[0].arn}:master_key::" },
      { name = "LITELLM_SALT_KEY", valueFrom = "${aws_secretsmanager_secret.litellm[0].arn}:salt_key::" },
      { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.litellm[0].arn}:database_url::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.litellm[0].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "litellm"
      }
    }
  }])
}

resource "aws_ecs_service" "litellm" {
  count           = local.litellm ? 1 : 0
  name            = "litellm"
  cluster         = aws_ecs_cluster.llm[0].id
  task_definition = aws_ecs_task_definition.litellm[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # one task; a new revision starts before the old one stops
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  # A revision whose tasks keep failing (e.g. the OOM crash loop) is rolled back to the last
  # working one, and Terraform fails in minutes instead of hanging until the llm_keys timeout.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # There is no load balancer or public path, so this is the way in for debugging:
  #   aws ecs execute-command --cluster <name>-llm --task <id> --container litellm --interactive --command sh
  enable_execute_command = true

  network_configuration {
    subnets          = local.private_subnet_ids
    security_groups  = [aws_security_group.litellm[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.litellm[0].arn
  }

  # The key bootstrap runs right after this: wait until the task is running.
  wait_for_steady_state = true

  depends_on = [
    aws_lambda_invocation.migrate, # LiteLLM's database and login exist
    aws_secretsmanager_secret_version.litellm,
    aws_iam_role_policy.litellm_exec_secrets,
    aws_vpc_security_group_ingress_rule.db_from_litellm,
  ]
}

# ── Virtual keys, created through LiteLLM's API ──────────────────────────────────────────
# Runs on create and whenever the key spec, the config or the master secret version changes.
resource "aws_lambda_invocation" "llm_keys" {
  count         = local.litellm ? 1 : 0
  function_name = aws_lambda_function.fn["llm_keys"].function_name
  qualifier     = aws_lambda_alias.live["llm_keys"].name
  input = jsonencode({
    spec_sha256    = sha256(local.llm_key_spec)
    task           = aws_ecs_service.litellm[0].task_definition
    secret_version = var.litellm_secret_version
  })

  depends_on = [aws_ecs_service.litellm, aws_iam_role_policy.fn]
}
