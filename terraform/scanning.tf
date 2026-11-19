# Org-wide SAST and DAST, run by the weekly Step Functions run before the collectors.
#
#   Prepare (Lambda) ─ exports the URLs teams registered in the dashboard to S3
#   Scan (Parallel)  ─ SAST: Fargate task, official semgrep image, every repo the GitHub App reads
#                    └ DAST: Fargate task, official ZAP image, baseline (passive) scan per URL
#   Collect          ─ the `sast` / `dast` collectors turn the raw results into findings
#
# Nothing to build: each task runs a small driver (src/scanner/*.py) that Terraform passes in
# an environment variable, like the LiteLLM config. A failed scan is recorded and the run goes
# on; its collector then fails, so nothing is marked fixed on missing data.

locals {
  scanning = var.sast_enabled || var.dast_enabled
  # The scheduler passes this list to the run; scanners add their collectors.
  run_collectors = distinct(concat(var.collectors, var.sast_enabled ? ["sast"] : [], var.dast_enabled ? ["dast"] : []))
  dashboard_url  = coalesce(var.dashboard_url, "https://${aws_cloudfront_distribution.web.domain_name}/")

  scan_tasks = { for k, v in {
    sast = var.sast_enabled ? {
      image  = var.semgrep_image
      cpu    = 4096
      memory = 8192
      script = file("${local.src_dir}/scanner/sast_scan.py")
      # the semgrep image is Alpine + Python; the driver needs boto3 and PyJWT for the App token
      deps = "boto3 PyJWT cryptography"
      env = {
        GITHUB_APP_ID             = var.github_app_id
        GITHUB_INSTALLATION_ID    = var.github_installation_id
        GITHUB_PRIVATE_KEY_SECRET = aws_secretsmanager_secret.github_private_key.arn
        SEMGREP_CONFIG            = var.semgrep_config
        SCAN_CONCURRENCY          = tostring(var.sast_concurrency)
        SCAN_MAX_REPOS            = tostring(var.sast_max_repos)
      }
      timeout_s = 6 * 3600
    } : null
    dast = var.dast_enabled ? {
      image  = var.zap_image
      cpu    = 2048
      memory = 4096
      script = file("${local.src_dir}/scanner/dast_scan.py")
      deps   = "boto3"
      env    = { DAST_MAX_TARGETS = tostring(var.dast_max_targets), ZAP_SPIDER_MINUTES = "1" }
      # 50 targets x ~2-3 min
      timeout_s = 3 * 3600
    } : null
  } : k => v if v != null }
}

resource "aws_ecs_cluster" "scan" {
  count = local.scanning ? 1 : 0
  name  = "${local.name}-scan"
}

resource "aws_cloudwatch_log_group" "scan" {
  for_each          = local.scan_tasks
  name              = "/ecs/${local.name}-${each.key}"
  retention_in_days = var.log_retention_days
}

# Outbound only: GitHub, the Semgrep registry, the scanned URLs, S3 and Secrets Manager (via NAT).
resource "aws_security_group" "scan" {
  count       = local.scanning ? 1 : 0
  name        = "${local.name}-scan"
  description = "SAST/DAST scan tasks: no inbound"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "scan_all" {
  count             = local.scanning ? 1 : 0
  security_group_id = aws_security_group.scan[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "GitHub, Semgrep registry, scan targets, AWS APIs"
}

resource "aws_iam_role" "scan_exec" {
  count              = local.scanning ? 1 : 0
  name               = "${local.name}-scan-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "scan_exec" {
  count      = local.scanning ? 1 : 0
  role       = aws_iam_role.scan_exec[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "scan_task" {
  for_each           = local.scan_tasks
  name               = "${local.name}-${each.key}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "scan_task" {
  for_each = local.scan_tasks
  name     = "scan"
  role     = aws_iam_role.scan_task[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat(
    [{ Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${aws_s3_bucket.data.arn}/runs/*/${each.key}-raw/*"] }],
    each.key == "sast" ? [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"],
    Resource = [aws_secretsmanager_secret.github_private_key.arn] }] : [],
    each.key == "dast" ? [{ Effect = "Allow", Action = ["s3:GetObject"],
    Resource = ["${aws_s3_bucket.data.arn}/config/dast_targets.json"] }] : [],
  ) })
}

resource "aws_ecs_task_definition" "scan" {
  for_each                 = local.scan_tasks
  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.scan_exec[0].arn
  task_role_arn            = aws_iam_role.scan_task[each.key].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  ephemeral_storage {
    size_in_gib = 50 # shallow clones of large repos
  }

  container_definitions = jsonencode([{
    name       = each.key
    image      = each.value.image
    essential  = true
    entryPoint = ["/bin/sh", "-c"]
    # pip may refuse system installs (PEP 668) on newer images; fall back to --break-system-packages.
    command = [join(" && ", [
      "(python3 -m pip install --quiet --disable-pip-version-check --user ${each.value.deps} || python3 -m pip install --quiet --disable-pip-version-check --user --break-system-packages ${each.value.deps})",
      each.key == "dast" ? "mkdir -p /zap/wrk" : "true",
      "printf '%s' \"$SCAN_SCRIPT\" > /tmp/scan.py",
      "exec python3 -u /tmp/scan.py",
    ])]
    environment = [for k, v in merge(each.value.env, {
      SCAN_SCRIPT = each.value.script
      DATA_BUCKET = aws_s3_bucket.data.bucket
      AWS_REGION  = var.aws_region
      RUN_ID      = "manual" # Step Functions overrides this with the execution name
    }) : { name = k, value = v }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.scan[each.key].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = each.key
      }
    }
  }])
}

# SES identity for the weekly team e-mails (a verification e-mail goes to this address, or
# set up the domain's DKIM records if it's a domain).
resource "aws_sesv2_email_identity" "digest" {
  count          = var.digest_sender == null ? 0 : 1
  email_identity = var.digest_sender
}

resource "aws_secretsmanager_secret" "jira" {
  count                   = var.jira_enabled ? 1 : 0
  name                    = "${local.name}/jira"
  description             = "Jira Cloud API credentials: {\"base_url\", \"email\", \"api_token\"}"
  recovery_window_in_days = var.secret_recovery_days
}

locals {
  # Step Functions states for the scans (empty when scanning is off).
  scan_branches = [for k, t in local.scan_tasks : {
    StartAt = "${upper(k)}Scan"
    States = {
      "${upper(k)}Scan" = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::ecs:runTask.sync"
        Parameters = {
          Cluster        = aws_ecs_cluster.scan[0].arn
          TaskDefinition = aws_ecs_task_definition.scan[k].arn
          LaunchType     = "FARGATE"
          NetworkConfiguration = { AwsvpcConfiguration = {
            Subnets        = local.private_subnet_ids
            SecurityGroups = [aws_security_group.scan[0].id]
            AssignPublicIp = "DISABLED"
          } }
          Overrides = { ContainerOverrides = [{
            Name        = k
            Environment = [{ Name = "RUN_ID", "Value.$" = "$$.Execution.Name" }]
          }] }
        }
        TimeoutSeconds = t.timeout_s
        ResultPath     = null
        Catch          = [{ ErrorEquals = ["States.ALL"], ResultPath = null, Next = "${upper(k)}ScanFailed" }]
        End            = true
      }
      # The collector finds no manifest, fails, and closes nothing; the run continues.
      "${upper(k)}ScanFailed" = { Type = "Pass", End = true }
    }
  }]
}
