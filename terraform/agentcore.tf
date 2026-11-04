# Amazon Bedrock AgentCore: the chat agent and the fix agent run on AgentCore Runtime,
# conversation memory lives in AgentCore Memory, and tools that reach outside the VPC
# (GitHub, SSM, the one GitHub write) are served by an AgentCore Gateway whose every call is
# checked by Cedar policies (AgentCore Policy, default deny).
#
#   browser ─▶ CloudFront ─▶ chat Lambda (auth, jobs, review API)
#                              │  user's Entra token
#                              ▼
#                    Runtime: audit agent (HTTP, JWT authorizer = Entra)
#                     │ SigV4 + scope token        │ A2A (SigV4)
#                     ▼                            ▼
#                Gateway (MCP, IAM) ◀────── Runtime: fix agent (LangGraph)
#                     │ Cedar policy per role
#                     ▼
#                tools Lambda ─▶ GitHub / SSM / GitHub write (approved fixes only)
#
# Database reads stay in-process (row-level security does the scoping). Tools behind the
# Gateway get the caller's scope as an HMAC-signed token and verify it themselves; Policy
# decides which agent may call which tool.

locals {
  agentcore = var.agentcore_enabled
  ac_name   = replace(local.name, "-", "_") # Runtime, Memory and Policy names allow letters, digits and _

  # One Gateway target per tool. The Gateway names tools "<target>___<tool>". Every entry has
  # the same shape (props as JSON) so the filtered result is a proper map for for_each.
  all_tool_targets = {
    gh-advisory = {
      enabled     = true
      tool        = "get_advisory"
      description = "Details of a GitHub security advisory: summary, severity, CVSS, affected and first patched versions."
      callers     = "read"
      props       = jsonencode([{ name = "ghsa_id", description = "GHSA id, e.g. GHSA-xxxx-xxxx-xxxx", required = true }])
    }
    gh-file = {
      enabled     = true
      tool        = "read_repo_file"
      description = "Read a file from one of the caller's team repos (default branch). Large files are truncated."
      callers     = "read+fix"
      props = jsonencode([{ name = "repo", description = "Repository name", required = true },
      { name = "path", description = "Path, e.g. package.json", required = true }])
    }
    gh-search = {
      enabled     = true
      tool        = "search_code"
      description = "Search one of the caller's team repos for an identifier."
      callers     = "read"
      props = jsonencode([{ name = "repo", description = "Repository name", required = true },
      { name = "query", description = "Identifier to look for", required = true }])
    }
    ops-instances = {
      enabled     = var.diagnostics_enabled
      tool        = "list_instances"
      description = "Servers the caller's team may run diagnostics on."
      callers     = "chat"
      props       = jsonencode([])
    }
    ops-diagnostic = {
      enabled     = var.diagnostics_enabled
      tool        = "run_diagnostic"
      description = "Run one read-only check on a server: disk_usage, memory, top_processes, listening_ports, uptime, service_status, recent_logs."
      callers     = "chat"
      props = jsonencode([{ name = "instance_id", description = "EC2 instance id", required = true },
        { name = "check", description = "One of the fixed checks", required = true },
      { name = "target", description = "Service or log name, for service_status and recent_logs", required = false }])
    }
    gh-write = {
      enabled     = var.fix_agent_enabled
      tool        = "open_fix_pr"
      description = "Open a pull request for a fix request a team lead approved. Refuses anything else."
      callers     = "fix"
      props       = jsonencode([{ name = "fix_request_id", description = "Approved fix request id", required = true }])
    }
  }
  tool_targets  = { for k, v in local.all_tool_targets : k => v if v.enabled }
  gateway_tools = { for t, v in local.tool_targets : v.tool => "${t}___${v.tool}" }

  runtime_url = local.agentcore ? {
    audit = "https://bedrock-agentcore.${var.aws_region}.amazonaws.com/runtimes/${urlencode(aws_bedrockagentcore_agent_runtime.audit[0].agent_runtime_arn)}/invocations?qualifier=DEFAULT"
    fix   = var.fix_agent_enabled ? "https://bedrock-agentcore.${var.aws_region}.amazonaws.com/runtimes/${urlencode(aws_bedrockagentcore_agent_runtime.fix[0].agent_runtime_arn)}/invocations/?qualifier=DEFAULT" : null
  } : { audit = null, fix = null }

  # Environment the Lambdas and the audit runtime share when AgentCore is on (nulls dropped).
  agentcore_env = { for k, v in {
    MEMORY_ID           = local.agentcore ? aws_bedrockagentcore_memory.chat[0].id : null
    GATEWAY_MCP_URL     = local.agentcore ? aws_bedrockagentcore_gateway.tools[0].gateway_url : null
    GATEWAY_TOOLS       = local.agentcore ? jsonencode(local.gateway_tools) : null
    SCOPE_KEY_SECRET    = local.agentcore ? aws_secretsmanager_secret.scope_key[0].arn : null
    FIX_AGENT_URL       = local.runtime_url.fix
    DIAGNOSTICS_ENABLED = var.diagnostics_enabled ? "true" : null
  } : k => v if v != null }

  state_machine_arn = "arn:${local.partition}:states:${var.aws_region}:${local.account_id}:stateMachine:${local.name}-weekly"
}

# ── Scope token key (never in Terraform state: generated ephemerally, written write-only) ──
resource "aws_secretsmanager_secret" "scope_key" {
  count                   = local.agentcore ? 1 : 0
  name                    = "${local.name}/scope-token-key"
  description             = "HMAC key for scope tokens between the agents and the Gateway tools (managed by Terraform)"
  recovery_window_in_days = var.secret_recovery_days
}

ephemeral "random_password" "scope_key" {
  count   = local.agentcore ? 1 : 0
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret_version" "scope_key" {
  count                    = local.agentcore ? 1 : 0
  secret_id                = aws_secretsmanager_secret.scope_key[0].id
  secret_string_wo         = ephemeral.random_password.scope_key[0].result
  secret_string_wo_version = var.scope_key_version
}

resource "aws_secretsmanager_secret" "fix_github_private_key" {
  count                   = local.agentcore && var.fix_agent_enabled ? 1 : 0
  name                    = "${local.name}/fix-github-app-private-key"
  description             = "PEM private key of the fix-bot GitHub App (Contents + Pull requests: write)"
  recovery_window_in_days = var.secret_recovery_days
}

# ── Runtime code: src/ plus dependencies built for arm64, zipped and uploaded to S3 ──────
locals {
  runtime_requirements = "${local.repo_root}/requirements-runtime.txt"
  otel_requirements    = "${local.repo_root}/requirements-otel.txt"
  runtime_zip          = "${local.build_dir}/agentcore-runtime.zip"
  runtime_hash = sha256(join("-", [
    filesha256(local.runtime_requirements), filesha256(local.requirements), filesha256(local.otel_requirements),
    data.archive_file.code.output_base64sha256, var.agentcore_runtime_python, tostring(var.agentcore_tracing),
  ]))
  # With tracing, the entry point runs the agent under opentelemetry-instrument.
  entry = { for k, f in { audit = "agent_main.py", fix = "fix_main.py" } :
  k => var.agentcore_tracing ? ["opentelemetry-instrument", f] : [f] }
  otel_env = { for k, v in {
    AGENT_OBSERVABILITY_ENABLED = "true"
    OTEL_PYTHON_DISTRO          = "aws_distro"
    OTEL_PYTHON_CONFIGURATOR    = "aws_configurator"
    OTEL_EXPORTER_OTLP_PROTOCOL = "http/protobuf"
  } : k => v if var.agentcore_tracing }
}

resource "terraform_data" "runtime_build" {
  count            = local.agentcore ? 1 : 0
  triggers_replace = [local.runtime_hash]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      B="${local.build_dir}/runtime"
      rm -rf "$B" && mkdir -p "$B"
      python3 -m pip install --quiet --disable-pip-version-check -r "${local.runtime_requirements}" \
        ${var.agentcore_tracing ? "-r \"${local.otel_requirements}\"" : ""} \
        --target "$B" --platform manylinux2014_aarch64 --implementation cp \
        --python-version ${var.agentcore_runtime_python} --only-binary=:all:
      cp -R "${local.src_dir}/." "$B/"
      find "$B" -name __pycache__ -prune -exec rm -rf {} +
      cd "$B" && rm -f "${abspath(local.runtime_zip)}" && zip -qr "${abspath(local.runtime_zip)}" .
    EOT
  }
}

resource "aws_s3_object" "runtime_code" {
  count       = local.agentcore ? 1 : 0
  bucket      = aws_s3_bucket.data.id
  key         = "agentcore/runtime-${substr(local.runtime_hash, 0, 16)}.zip"
  source      = local.runtime_zip
  source_hash = local.runtime_hash

  depends_on = [terraform_data.runtime_build]
}

# ── IAM: the service role trust, runtime roles, gateway role ─────────────────────────────
data "aws_iam_policy_document" "agentcore_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:bedrock-agentcore:${var.aws_region}:${local.account_id}:*"]
    }
  }
}

locals {
  runtime_roles = local.agentcore ? toset(concat(["audit"], var.fix_agent_enabled ? ["fix"] : [])) : toset([])

  runtime_base_statements = [
    { actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams", "logs:DescribeLogGroups"],
    resources = ["arn:${local.partition}:logs:${var.aws_region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"] },
    { actions = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"], resources = ["*"] },
    { actions = ["s3:GetObject"], resources = ["${aws_s3_bucket.data.arn}/agentcore/*"] },
    { actions = ["rds-db:connect"], resources = ["${local.db_user_arn}/${local.app_db_user}"] },
    { actions = ["bedrock:InvokeModel"], resources = var.llm_backend == "bedrock" ? [
      "arn:${local.partition}:bedrock:*::foundation-model/*",
      "arn:${local.partition}:bedrock:*:${local.account_id}:inference-profile/*",
    ] : [] },
    { actions = ["bedrock-agentcore:InvokeGateway"], resources = local.agentcore ? [aws_bedrockagentcore_gateway.tools[0].gateway_arn] : [] },
  ]

  runtime_statements = {
    audit = concat(local.runtime_base_statements, [
      { actions = ["secretsmanager:GetSecretValue"], resources = compact([
        aws_secretsmanager_secret.gateway_keys.arn, aws_secretsmanager_secret.github_private_key.arn,
      local.agentcore ? aws_secretsmanager_secret.scope_key[0].arn : ""]) },
      { actions = ["bedrock-agentcore:CreateEvent", "bedrock-agentcore:ListEvents", "bedrock-agentcore:GetEvent",
        "bedrock-agentcore:RetrieveMemoryRecords"],
      resources = local.agentcore ? [aws_bedrockagentcore_memory.chat[0].arn] : [] },
      # A name pattern, not the resource's ARN: both runtimes depend on these role policies.
      { actions = ["bedrock-agentcore:InvokeAgentRuntime"], resources = local.agentcore && var.fix_agent_enabled ? [
        "arn:${local.partition}:bedrock-agentcore:${var.aws_region}:${local.account_id}:runtime/${local.ac_name}_fix-*",
      "arn:${local.partition}:bedrock-agentcore:${var.aws_region}:${local.account_id}:runtime/${local.ac_name}_fix-*/*"] : [] },
    ])
    fix = concat(local.runtime_base_statements, [
      { actions = ["secretsmanager:GetSecretValue"], resources = compact([
      aws_secretsmanager_secret.gateway_keys.arn, local.agentcore ? aws_secretsmanager_secret.scope_key[0].arn : ""]) },
    ])
  }
}

resource "aws_iam_role" "runtime" {
  for_each           = local.runtime_roles
  name               = "${local.name}-runtime-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume.json
}

data "aws_iam_policy_document" "runtime" {
  for_each = local.runtime_roles
  dynamic "statement" {
    for_each = [for s in local.runtime_statements[each.key] : s if length(s.resources) > 0]
    content {
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["bedrock-agentcore"]
    }
  }
}

resource "aws_iam_role_policy" "runtime" {
  for_each = local.runtime_roles
  name     = "access"
  role     = aws_iam_role.runtime[each.key].id
  policy   = data.aws_iam_policy_document.runtime[each.key].json
}

# ── Runtime: the audit (chat) agent ─────────────────────────────────────────────────────
resource "aws_bedrockagentcore_agent_runtime" "audit" {
  count              = local.agentcore ? 1 : 0
  agent_runtime_name = "${local.ac_name}_audit"
  description        = "DevOps audit chat agent (ReAct harness, confidence gate)"
  role_arn           = aws_iam_role.runtime["audit"].arn

  agent_runtime_artifact {
    code_configuration {
      entry_point = local.entry.audit
      runtime     = "PYTHON_${replace(var.agentcore_runtime_python, ".", "_")}"
      code {
        s3 {
          bucket = aws_s3_bucket.data.bucket
          prefix = aws_s3_object.runtime_code[0].key
        }
      }
    }
  }

  # Only requests with a valid Entra access token for this app reach the agent; the agent
  # verifies the token again and resolves the user's teams from it.
  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = "https://login.microsoftonline.com/${var.entra_tenant_id}/v2.0/.well-known/openid-configuration"
      allowed_audience = [var.entra_client_id]
    }
  }

  request_header_configuration {
    request_header_allowlist = ["Authorization"]
  }

  protocol_configuration {
    server_protocol = "HTTP"
  }

  network_configuration {
    network_mode = "VPC"
    network_mode_config {
      subnets         = local.private_subnet_ids
      security_groups = [aws_security_group.lambda.id]
    }
  }

  lifecycle_configuration {
    idle_runtime_session_timeout = 900
    max_lifetime                 = 3600
  }

  environment_variables = merge(local.agent_env, local.agentcore_env, local.otel_env, {
    AUDIT_AWS_REGION  = var.aws_region
    OTEL_SERVICE_NAME = "${local.name}-audit-agent"
  })

  depends_on = [aws_iam_role_policy.runtime]
}

# ── Runtime: the fix agent (LangGraph, A2A, IAM-only) ───────────────────────────────────
resource "aws_bedrockagentcore_agent_runtime" "fix" {
  count              = local.agentcore && var.fix_agent_enabled ? 1 : 0
  agent_runtime_name = "${local.ac_name}_fix"
  description        = "Drafts dependency fixes and opens PRs after a team lead approves (A2A)"
  role_arn           = aws_iam_role.runtime["fix"].arn

  agent_runtime_artifact {
    code_configuration {
      entry_point = local.entry.fix
      runtime     = "PYTHON_${replace(var.agentcore_runtime_python, ".", "_")}"
      code {
        s3 {
          bucket = aws_s3_bucket.data.bucket
          prefix = aws_s3_object.runtime_code[0].key
        }
      }
    }
  }

  protocol_configuration {
    server_protocol = "A2A"
  }

  network_configuration {
    network_mode = "VPC"
    network_mode_config {
      subnets         = local.private_subnet_ids
      security_groups = [aws_security_group.lambda.id]
    }
  }

  environment_variables = merge(local.db_env, local.otel_env, {
    OTEL_SERVICE_NAME   = "${local.name}-fix-agent"
    DB_USER             = local.app_db_user
    AUDIT_AWS_REGION    = var.aws_region
    LLM_BACKEND         = var.llm_backend
    GATEWAY_URL         = coalesce(var.gateway_url, "unused")
    GATEWAY_KEYS_SECRET = aws_secretsmanager_secret.gateway_keys.arn
    BATCH_MODEL         = var.batch_model
    GATEWAY_MCP_URL     = aws_bedrockagentcore_gateway.tools[0].gateway_url
    GATEWAY_TOOLS       = jsonencode(local.gateway_tools)
    SCOPE_KEY_SECRET    = aws_secretsmanager_secret.scope_key[0].arn
  })

  depends_on = [aws_iam_role_policy.runtime]
}

# ── Memory: short-term events per user and session; optional long-term strategies ───────
resource "aws_bedrockagentcore_memory" "chat" {
  count                 = local.agentcore ? 1 : 0
  name                  = "${local.ac_name}_chat"
  description           = "Chat turns per user (actor) and session"
  event_expiry_duration = var.memory_event_expiry_days
}

resource "aws_bedrockagentcore_memory_strategy" "preferences" {
  count               = local.agentcore && var.agentcore_memory_long_term ? 1 : 0
  name                = "user_preferences"
  memory_id           = aws_bedrockagentcore_memory.chat[0].id
  type                = "USER_PREFERENCE"
  description         = "What each user cares about (recalled as context only, never as evidence)"
  namespace_templates = ["/users/{actorId}/"]
}

resource "aws_bedrockagentcore_memory_strategy" "summaries" {
  count               = local.agentcore && var.agentcore_memory_long_term ? 1 : 0
  name                = "session_summaries"
  memory_id           = aws_bedrockagentcore_memory.chat[0].id
  type                = "SUMMARIZATION"
  namespace_templates = ["/summaries/{actorId}/{sessionId}/"]
}

# ── Gateway (MCP, IAM auth) with Policy ─────────────────────────────────────────────────
resource "aws_iam_role" "gateway" {
  count              = local.agentcore ? 1 : 0
  name               = "${local.name}-gateway"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume.json
}

resource "aws_iam_role_policy" "gateway" {
  count = local.agentcore ? 1 : 0
  name  = "invoke-tools-and-authorize"
  role  = aws_iam_role.gateway[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_alias.tools[0].arn },
      { Effect = "Allow",
        Action = ["bedrock-agentcore:AuthorizeAction", "bedrock-agentcore:PartiallyAuthorizeActions", "bedrock-agentcore:GetPolicyEngine"],
      Resource = [aws_bedrockagentcore_policy_engine.tools[0].policy_engine_arn, "${aws_bedrockagentcore_policy_engine.tools[0].policy_engine_arn}/*"] },
    ]
  })
}

resource "aws_bedrockagentcore_policy_engine" "tools" {
  count       = local.agentcore ? 1 : 0
  name        = "${local.ac_name}_tools"
  description = "Which agent may call which Gateway tool (default deny)"
}

resource "aws_bedrockagentcore_gateway" "tools" {
  count           = local.agentcore ? 1 : 0
  name            = "${local.name}-tools"
  description     = "GitHub, SSM and fix-PR tools for the DevOps audit agents"
  role_arn        = aws_iam_role.gateway[0].arn
  authorizer_type = "AWS_IAM"
  protocol_type   = "MCP"

  policy_engine_configuration {
    arn  = aws_bedrockagentcore_policy_engine.tools[0].policy_engine_arn
    mode = var.agentcore_policy_mode
  }

  depends_on = [aws_iam_role_policy.gateway]
}

resource "aws_bedrockagentcore_gateway_target" "tool" {
  for_each           = { for k, v in local.tool_targets : k => v if local.agentcore }
  name               = each.key
  gateway_identifier = aws_bedrockagentcore_gateway.tools[0].gateway_id
  description        = each.value.description

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_alias.tools[0].arn
        tool_schema {
          inline_payload {
            name        = each.value.tool
            description = each.value.description
            input_schema {
              type = "object"
              dynamic "property" {
                for_each = jsondecode(each.value.props)
                content {
                  name        = property.value.name
                  type        = "string"
                  description = property.value.description
                  required    = property.value.required
                }
              }
              property {
                name        = "_scope"
                type        = "string"
                description = "Signed scope token added by the agent harness (not chosen by the model)"
                required    = true
              }
            }
          }
        }
      }
    }
  }
}

# Cedar policies: the caller is the IAM role session of the Lambda or runtime making the call.
locals {
  # Role names as strings (they are fixed by name_prefix), so policies add no graph edges.
  role_names = {
    chat          = "${local.name}-chat"
    investigate   = "${local.name}-investigate"
    audit_runtime = "${local.name}-runtime-audit"
    fix_runtime   = var.fix_agent_enabled ? "${local.name}-runtime-fix" : ""
  }
  role_session = { for k, n in local.role_names : k => "arn:${local.partition}:sts::${local.account_id}:assumed-role/${n}/*" if n != "" }

  policy_sets = { for name, p in {
    read_tools = {
      description = "Chat and investigation agents may use the GitHub read tools"
      callers     = [local.role_session.chat, local.role_session.investigate, local.role_session.audit_runtime]
      targets     = tolist([for t, v in local.tool_targets : t if contains(["read", "read+fix"], v.callers)])
    }
    ops_tools = {
      description = "Only the chat agent may run server diagnostics"
      callers     = [local.role_session.chat, local.role_session.audit_runtime]
      targets     = tolist([for t, v in local.tool_targets : t if v.callers == "chat"])
    }
    fix_tools = {
      description = "Only the fix agent may read the manifest and open an approved fix PR"
      callers     = compact([lookup(local.role_session, "fix_runtime", "")])
      targets     = tolist([for t, v in local.tool_targets : t if contains(["fix", "read+fix"], v.callers)])
    }
  } : name => p if local.agentcore && length(p.targets) > 0 && length(p.callers) > 0 }
}

resource "aws_bedrockagentcore_policy" "tools" {
  for_each         = local.policy_sets
  name             = each.key
  policy_engine_id = aws_bedrockagentcore_policy_engine.tools[0].policy_engine_id
  description      = each.value.description

  definition {
    cedar {
      statement = <<-EOT
        permit(
          principal is AgentCore::IamEntity,
          action in [${join(", ", [for t in each.value.targets : "AgentCore::Action::\"${t}___${local.tool_targets[t].tool}\""])}],
          resource == AgentCore::Gateway::"${aws_bedrockagentcore_gateway.tools[0].gateway_arn}"
        ) when {
          ${join(" || ", [for c in each.value.callers : "principal.id like \"${c}\""])}
        };
      EOT
    }
  }

  depends_on = [aws_bedrockagentcore_gateway_target.tool]
}

# ── The Lambda behind every Gateway target ──────────────────────────────────────────────
# Its own resources (not in local.functions): the chat Lambda's environment points at the
# runtime and gateway, which point back here, and a for_each resource is one graph node.
locals {
  tools_env = merge(local.db_env, local.github_env, {
    DB_USER                = local.app_db_user
    SCOPE_KEY_SECRET       = local.agentcore ? aws_secretsmanager_secret.scope_key[0].arn : ""
    DIAGNOSTICS_DOCUMENT   = var.diagnostics_enabled ? aws_ssm_document.diagnostics[0].name : ""
    DIAGNOSTIC_SERVICES    = join(",", var.diagnostic_services)
    DIAGNOSTIC_LOGS        = join(",", keys(var.diagnostic_logs))
    GITHUB_MAX_RATE_WAIT_S = "15"
    }, { for k, v in {
      FIX_GITHUB_APP_ID             = var.fix_github_app_id
      FIX_GITHUB_INSTALLATION_ID    = var.fix_github_installation_id
      FIX_GITHUB_PRIVATE_KEY_SECRET = local.agentcore && var.fix_agent_enabled ? aws_secretsmanager_secret.fix_github_private_key[0].arn : null
  } : k => v if v != null })
}

resource "aws_cloudwatch_log_group" "tools" {
  count             = local.agentcore ? 1 : 0
  name              = "/aws/lambda/${local.name}-gateway-tools"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "tools" {
  count              = local.agentcore ? 1 : 0
  name               = "${local.name}-gateway-tools"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "tools_base" {
  count      = local.agentcore ? 1 : 0
  role       = aws_iam_role.tools[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "aws_iam_policy_document" "tools" {
  count = local.agentcore ? 1 : 0
  statement {
    actions   = ["rds-db:connect"]
    resources = ["${local.db_user_arn}/${local.app_db_user}"]
  }
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = compact([
      aws_secretsmanager_secret.github_private_key.arn, aws_secretsmanager_secret.scope_key[0].arn,
      var.fix_agent_enabled ? aws_secretsmanager_secret.fix_github_private_key[0].arn : "",
    ])
  }
  dynamic "statement" {
    for_each = var.diagnostics_enabled ? [1] : []
    content {
      actions   = ["ssm:SendCommand"]
      resources = ["arn:${local.partition}:ssm:${var.aws_region}:${local.account_id}:document/${aws_ssm_document.diagnostics[0].name}"]
    }
  }
  dynamic "statement" {
    for_each = var.diagnostics_enabled ? [1] : []
    content {
      # Run Command only on instances explicitly tagged for agent diagnostics.
      actions   = ["ssm:SendCommand"]
      resources = ["arn:${local.partition}:ec2:${var.aws_region}:${local.account_id}:instance/*"]
      condition {
        test     = "StringEquals"
        variable = "ssm:resourceTag/agent-diagnostics"
        values   = ["allowed"]
      }
    }
  }
  dynamic "statement" {
    for_each = var.diagnostics_enabled ? [1] : []
    content {
      actions   = ["ssm:GetCommandInvocation", "ec2:DescribeInstances"]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "tools" {
  count  = local.agentcore ? 1 : 0
  name   = "access"
  role   = aws_iam_role.tools[0].id
  policy = data.aws_iam_policy_document.tools[0].json
}

resource "aws_lambda_function" "tools" {
  count            = local.agentcore ? 1 : 0
  function_name    = "${local.name}-gateway-tools"
  role             = aws_iam_role.tools[0].arn
  runtime          = "python${var.lambda_python_version}"
  architectures    = [var.lambda_architecture]
  handler          = "audit_agent.handlers.gateway_tools.handler"
  filename         = data.archive_file.code.output_path
  source_code_hash = data.archive_file.code.output_base64sha256
  layers           = [aws_lambda_layer_version.deps.arn]
  timeout          = 60
  memory_size      = 512
  publish          = true

  environment {
    variables = local.tools_env
  }

  vpc_config {
    subnet_ids         = local.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  depends_on = [aws_cloudwatch_log_group.tools, aws_iam_role_policy_attachment.tools_base]
}

resource "aws_lambda_alias" "tools" {
  count            = local.agentcore ? 1 : 0
  name             = "live"
  function_name    = aws_lambda_function.tools[0].function_name
  function_version = aws_lambda_function.tools[0].version
}
