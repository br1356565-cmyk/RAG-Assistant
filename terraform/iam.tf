# One role per function, least privilege.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fn" {
  for_each           = local.functions
  name               = "${local.name}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "fn_base" {
  for_each   = local.functions
  role       = aws_iam_role.fn[each.key].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/${each.value.in_vpc ? "AWSLambdaVPCAccessExecutionRole" : "AWSLambdaBasicExecutionRole"}"
}

locals {
  agent_statements = [
    { actions = ["rds-db:connect"], resources = ["${local.db_user_arn}/${local.app_db_user}"] },
    { actions = ["secretsmanager:GetSecretValue"], resources = [
      aws_secretsmanager_secret.gateway_keys.arn, aws_secretsmanager_secret.github_private_key.arn] },
    # Direct Bedrock backend only. Cross-region inference profiles route to the foundation
    # model in several regions, so the model ARN is allowed in any region.
    { actions = ["bedrock:InvokeModel"], resources = var.llm_backend == "bedrock" ? [
      "arn:${local.partition}:bedrock:*::foundation-model/*",
      "arn:${local.partition}:bedrock:*:${local.account_id}:inference-profile/*",
    ] : [] },
  ]

  fn_statements = tomap({
    chat        = local.agent_statements
    investigate = local.agent_statements
    ingest = [
      { actions = ["rds-db:connect"], resources = ["${local.db_user_arn}/${local.ingest_db_user}"] },
      { actions = ["s3:GetObject"], resources = ["${aws_s3_bucket.data.arn}/runs/*"] },
    ]
    collect = [
      { actions = ["s3:PutObject"], resources = ["${aws_s3_bucket.data.arn}/runs/*"] },
      { actions = ["secretsmanager:GetSecretValue"], resources = [aws_secretsmanager_secret.github_private_key.arn] },
      { actions = ["sts:AssumeRole"], resources = var.security_audit_role_arn == null ? [] : [var.security_audit_role_arn] },
      # used only when no security_audit_role_arn is set (GuardDuty read in this account)
      { actions = ["guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings"], resources = ["*"] },
    ]
    notify = [
      { actions = ["secretsmanager:GetSecretValue"], resources = [aws_secretsmanager_secret.slack_webhook.arn] },
    ]
    migrate = [
      { actions = ["secretsmanager:GetSecretValue"], resources = [aws_db_instance.db.master_user_secret[0].secret_arn] },
    ]
  })
}

data "aws_iam_policy_document" "fn" {
  for_each = local.fn_statements
  dynamic "statement" {
    for_each = [for s in each.value : s if length(s.resources) > 0]
    content {
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
}

resource "aws_iam_role_policy" "fn" {
  for_each = local.fn_statements
  name     = "access"
  role     = aws_iam_role.fn[each.key].id
  policy   = data.aws_iam_policy_document.fn[each.key].json
}
