# Weekly run: Scheduler -> Step Functions
#   Prepare (exports dashboard-registered DAST URLs to S3; never fatal)
#   -> Scan (scanning.tf: SAST + DAST Fargate tasks in parallel; only when enabled; never fatal)
#   -> Collect (Map over collectors; a failed collector is recorded, not fatal)
#   -> Ingest (lifecycle, owners, aggregates, investigation queue)
#   -> Investigate (Map over the queue, bounded concurrency; failures recorded)
#   -> ReviewGate (waits, up to review_gate_timeout_hours, until a team lead has reviewed every
#      low-confidence investigation; continues at once when there are none)
#   -> Deliver (Jira sync, then each team's e-mail/Slack report from the dashboard settings)
#   -> Notify (Slack summary). If ingest fails: NotifyFailure, then the execution fails.

locals {
  alias_arn = { for k, a in aws_lambda_alias.live : k => a.arn }

  lambda_retry = {
    ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
    IntervalSeconds = 5
    MaxAttempts     = 3
    BackoffRate     = 2
  }

  state_machine = {
    Comment = "Weekly DevOps audit run"
    StartAt = "Prepare"
    States = merge({
      Prepare = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.alias_arn["prepare"]
          Payload      = { "run_id.$" = "$$.Execution.Name" }
        }
        ResultPath = null
        Retry      = [local.lambda_retry]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = null, Next = local.scanning ? "Scan" : "Collect" }]
        Next       = local.scanning ? "Scan" : "Collect"
      }
      }, { for k, v in {
        Scan = {
          Type       = "Parallel"
          Branches   = local.scan_branches
          ResultPath = null
          Next       = "Collect"
        }
      } : k => v if local.scanning }, {
      Collect = {
        Type      = "Map"
        ItemsPath = "$.collectors"
        ItemSelector = {
          "collector.$" = "$$.Map.Item.Value"
          "run_id.$"    = "$$.Execution.Name"
        }
        MaxConcurrency = 3
        ItemProcessor = {
          ProcessorConfig = { Mode = "INLINE" }
          StartAt         = "RunCollector"
          States = {
            RunCollector = {
              Type     = "Task"
              Resource = "arn:${local.partition}:states:::lambda:invoke"
              Parameters = {
                FunctionName = local.alias_arn["collect"]
                "Payload.$"  = "$"
              }
              ResultSelector = {
                "collector.$" = "$.Payload.collector"
                "status.$"    = "$.Payload.status"
                "key.$"       = "$.Payload.key"
                "count.$"     = "$.Payload.count"
                "complete.$"  = "$.Payload.complete"
              }
              Retry = [
                local.lambda_retry,
                { ErrorEquals = ["States.TaskFailed"], IntervalSeconds = 60, MaxAttempts = 1, BackoffRate = 1 },
              ]
              Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "CollectorFailed" }]
              End   = true
            }
            CollectorFailed = {
              Type = "Pass"
              Parameters = {
                "collector.$" = "$.collector"
                status        = "failed"
                "error.$"     = "$.error.Cause"
              }
              End = true
            }
          }
        }
        ResultPath = "$.collected"
        Next       = "Ingest"
      }

      Ingest = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.alias_arn["ingest"]
          Payload = {
            "run_id.$"  = "$$.Execution.Name"
            "results.$" = "$.collected"
          }
        }
        ResultSelector = { "summary.$" = "$.Payload" }
        ResultPath     = "$.ingest"
        Retry          = [local.lambda_retry]
        Catch          = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
        Next           = "Investigate"
      }

      Investigate = {
        Type           = "Map"
        ItemsPath      = "$.ingest.summary.investigate"
        MaxConcurrency = var.investigate_max_concurrency
        ItemProcessor = {
          ProcessorConfig = { Mode = "INLINE" }
          StartAt         = "InvestigateOne"
          States = {
            InvestigateOne = {
              Type     = "Task"
              Resource = "arn:${local.partition}:states:::lambda:invoke"
              Parameters = {
                FunctionName = local.alias_arn["investigate"]
                "Payload.$"  = "$"
              }
              ResultSelector = {
                "status.$"      = "$.Payload.status"
                "fingerprint.$" = "$.Payload.fingerprint"
              }
              Retry = [local.lambda_retry]
              Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "InvestigationFailed" }]
              End   = true
            }
            InvestigationFailed = {
              Type = "Pass"
              Parameters = {
                "fingerprint.$" = "$.fingerprint"
                status          = "failed"
              }
              End = true
            }
          }
        }
        ResultPath = "$.investigations"
        Next       = "ReviewGate"
      }

      # Human review: the task token is stored; the review API completes it when the last
      # pending investigation is decided. A timeout or error never fails the run.
      ReviewGate = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke.waitForTaskToken"
        Parameters = {
          FunctionName = local.alias_arn["review_gate"]
          Payload = {
            "run_id.$"     = "$$.Execution.Name"
            "task_token.$" = "$$.Task.Token"
          }
        }
        TimeoutSeconds = var.review_gate_timeout_hours * 3600
        ResultPath     = "$.review"
        Retry          = [local.lambda_retry]
        Catch = [
          { ErrorEquals = ["States.Timeout"], ResultPath = "$.review", Next = "Deliver" },
          { ErrorEquals = ["States.ALL"], ResultPath = "$.review", Next = "Deliver" },
        ]
        Next = "Deliver"
      }

      # Team reports and Jira. Errors are reported in the summary, never fail the run.
      Deliver = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.alias_arn["deliver"]
          Payload = {
            "run_id.$"    = "$$.Execution.Name"
            dashboard_url = local.dashboard_url
          }
        }
        ResultSelector = {
          "digest.$" = "$.Payload.digest"
          "jira.$"   = "$.Payload.jira"
        }
        ResultPath = "$.delivery"
        Retry      = [local.lambda_retry]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.delivery", Next = "Notify" }]
        Next       = "Notify"
      }

      Notify = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.alias_arn["notify"]
          Payload = {
            "run_id.$"         = "$$.Execution.Name"
            "ingest.$"         = "$.ingest.summary"
            "investigations.$" = "$.investigations"
            "review.$"         = "$.review"
            "delivery.$"       = "$.delivery"
          }
        }
        Retry = [local.lambda_retry]
        End   = true
      }

      NotifyFailure = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.alias_arn["notify"]
          Payload = {
            "run_id.$" = "$$.Execution.Name"
            "error.$"  = "$.error"
          }
        }
        Retry = [local.lambda_retry]
        Next  = "Failed"
      }

      Failed = {
        Type  = "Fail"
        Error = "AuditRunFailed"
        Cause = "Ingest failed; the Slack message and the NotifyFailure input have the details."
      }
    })
  }
}

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${local.name}-weekly"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${local.name}-weekly-sfn"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

data "aws_iam_policy_document" "sfn" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [for k in ["prepare", "collect", "ingest", "investigate", "review_gate", "deliver", "notify"] : local.alias_arn[k]]
  }
  # ecs:runTask.sync for the scan tasks (scanning.tf)
  dynamic "statement" {
    for_each = local.scanning ? [1] : []
    content {
      actions   = ["ecs:RunTask"]
      resources = [for k, t in aws_ecs_task_definition.scan : "${t.arn_without_revision}:*"]
    }
  }
  dynamic "statement" {
    for_each = local.scanning ? [1] : []
    content {
      actions   = ["ecs:StopTask", "ecs:DescribeTasks"]
      resources = ["*"]
    }
  }
  dynamic "statement" {
    for_each = local.scanning ? [1] : []
    content {
      actions   = ["iam:PassRole"]
      resources = concat([aws_iam_role.scan_exec[0].arn], [for k, r in aws_iam_role.scan_task : r.arn])
    }
  }
  dynamic "statement" {
    for_each = local.scanning ? [1] : []
    content {
      actions   = ["events:PutTargets", "events:PutRule", "events:DescribeRule"]
      resources = ["arn:${local.partition}:events:${var.aws_region}:${local.account_id}:rule/StepFunctionsGetEventsForECSTaskRule"]
    }
  }
  statement {
    # Required by Step Functions to deliver execution logs to CloudWatch Logs.
    actions = [
      "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "invoke-and-log"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

resource "aws_sfn_state_machine" "weekly" {
  name       = "${local.name}-weekly"
  role_arn   = aws_iam_role.sfn.arn
  type       = "STANDARD"
  definition = jsonencode(local.state_machine)

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = false # payloads include finding titles; keep them out of logs
    level                  = "ERROR"
  }

  depends_on = [aws_iam_role_policy.sfn]
}

# ── Schedule ───────────────────────────────────────────────────────────────
data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${local.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  name = "start-weekly-run"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "states:StartExecution", Resource = aws_sfn_state_machine.weekly.arn }]
  })
}

resource "aws_scheduler_schedule" "weekly" {
  name                         = "${local.name}-weekly"
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_sfn_state_machine.weekly.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ collectors = local.run_collectors })
  }
}
