# Alarms for the cases the Slack summary can't cover: the run itself failing, or chat errors.

resource "aws_sns_topic" "alarms" {
  name = "${local.name}-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == null ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "weekly_run_failed" {
  alarm_name          = "${local.name}-weekly-run-failed"
  alarm_description   = "The weekly audit run failed or timed out."
  namespace           = "AWS/States"
  metric_name         = "ExecutionsFailed"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.weekly.arn }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "weekly_run_timed_out" {
  alarm_name          = "${local.name}-weekly-run-timed-out"
  namespace           = "AWS/States"
  metric_name         = "ExecutionsTimedOut"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.weekly.arn }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "chat_errors" {
  alarm_name          = "${local.name}-chat-errors"
  alarm_description   = "Chat Lambda is erroring."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.fn["chat"].function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

# ── Agent metrics from structured log lines (one JSON line per event) ──────────────────
# chat_job is logged by the chat Lambda for every answered question, whether the agent ran
# in the Lambda or on AgentCore Runtime, so these cover both paths.
locals {
  metric_ns = "DevOpsAudit/${local.name}"

  metric_filters = merge(
    {
      questions            = { group = "chat", pattern = "{ $.event = \"chat_job\" }", value = "1" }
      answer_errors        = { group = "chat", pattern = "{ $.event = \"chat_job\" && $.status = \"error\" }", value = "1" }
      unfinished_answers   = { group = "chat", pattern = "{ $.event = \"chat_job\" && $.status = \"done\" && $.answer_status != \"answered\" }", value = "1" }
      low_confidence       = { group = "chat", pattern = "{ $.event = \"chat_job\" && $.low_confidence IS TRUE }", value = "1" }
      confidence_retries   = { group = "chat", pattern = "{ $.event = \"chat_job\" && $.retries > 0 }", value = "$.retries" }
      answer_latency_ms    = { group = "chat", pattern = "{ $.event = \"chat_job\" }", value = "$.ms" }
      chat_tokens          = { group = "chat", pattern = "{ $.event = \"chat_job\" }", value = "$.tokens" }
      feedback_up          = { group = "chat", pattern = "{ $.event = \"feedback\" && $.rating = 1 }", value = "1" }
      feedback_down        = { group = "chat", pattern = "{ $.event = \"feedback\" && $.rating = -1 }", value = "1" }
      investigations       = { group = "investigate", pattern = "{ $.event = \"investigate\" }", value = "1" }
      investigation_low    = { group = "investigate", pattern = "{ $.event = \"investigate\" && $.low_confidence IS TRUE }", value = "1" }
      investigation_failed = { group = "investigate", pattern = "{ $.event = \"investigate\" && $.status != \"submitted\" }", value = "1" }
      investigation_tokens = { group = "investigate", pattern = "{ $.event = \"investigate\" }", value = "$.tokens" }
      review_pending       = { group = "review_gate", pattern = "{ $.event = \"review_gate\" }", value = "$.pending" }
    },
    { for k, v in {
      gateway_tool_calls  = { group = "tools", pattern = "{ $.event = \"gateway_tool\" }", value = "1" }
      gateway_tool_denied = { group = "tools", pattern = "{ $.event = \"gateway_tool_denied\" }", value = "1" }
    } : k => v if local.agentcore },
  )

  log_group_names = merge(
    { for k, g in aws_cloudwatch_log_group.fn : k => g.name },
    { for k, g in aws_cloudwatch_log_group.tools : "tools" => g.name },
  )
  metric_name = { for k, _ in local.metric_filters : k => replace(title(replace(k, "_", " ")), " ", "") }
}

resource "aws_cloudwatch_log_metric_filter" "agent" {
  for_each       = local.metric_filters
  name           = "${local.name}-${each.key}"
  log_group_name = local.log_group_names[each.value.group]
  pattern        = each.value.pattern

  metric_transformation {
    namespace = local.metric_ns
    name      = local.metric_name[each.key]
    value     = each.value.value
    unit      = each.key == "answer_latency_ms" ? "Milliseconds" : "None"
  }
}

resource "aws_cloudwatch_metric_alarm" "gateway_denied" {
  count               = local.agentcore ? 1 : 0
  alarm_name          = "${local.name}-gateway-tool-denied"
  alarm_description   = "A Gateway tool refused a call (missing, forged or expired scope token). Expected never."
  namespace           = local.metric_ns
  metric_name         = local.metric_name["gateway_tool_denied"]
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.agent]
}

resource "aws_cloudwatch_metric_alarm" "answer_errors" {
  alarm_name          = "${local.name}-answer-errors"
  alarm_description   = "Several chat answers failed within 15 minutes."
  namespace           = local.metric_ns
  metric_name         = local.metric_name["answer_errors"]
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.agent]
}

resource "aws_cloudwatch_dashboard" "agent" {
  dashboard_name = "${local.name}-agent"
  dashboard_body = jsonencode({
    widgets = [
      { type = "text", x = 0, y = 0, width = 24, height = 2, properties = { markdown = join("", [
        "## DevOps audit agent\n",
        "Answers, confidence gate, human feedback and review. Answers below ${var.confidence_threshold * 100}% confidence ",
        "loop back up to ${var.max_confidence_retries} times; investigations still below it wait for a team lead.",
      ]) } },
      { type = "metric", x = 0, y = 2, width = 8, height = 6, properties = {
        title   = "Questions and outcomes (per hour)", region = var.aws_region, stat = "Sum", period = 3600, view = "timeSeries"
        metrics = [for k in ["questions", "low_confidence", "unfinished_answers", "answer_errors"] : [local.metric_ns, local.metric_name[k]]]
      } },
      { type = "metric", x = 8, y = 2, width = 8, height = 6, properties = {
        title = "Low-confidence answer rate (%)", region = var.aws_region, period = 86400, view = "timeSeries"
        metrics = [
          [local.metric_ns, local.metric_name["low_confidence"], { id = "low", stat = "Sum", visible = false }],
          [local.metric_ns, local.metric_name["questions"], { id = "all", stat = "Sum", visible = false }],
          [{ expression = "100 * low / all", label = "low confidence %", id = "rate" }],
        ]
      } },
      { type = "metric", x = 16, y = 2, width = 8, height = 6, properties = {
        title = "Answer latency (ms)", region = var.aws_region, period = 3600, view = "timeSeries"
        metrics = [
          [local.metric_ns, local.metric_name["answer_latency_ms"], { stat = "p50", label = "p50" }],
          [local.metric_ns, local.metric_name["answer_latency_ms"], { stat = "p90", label = "p90" }],
        ]
      } },
      { type = "metric", x = 0, y = 8, width = 8, height = 6, properties = {
        title   = "Feedback (per day)", region = var.aws_region, stat = "Sum", period = 86400, view = "bar"
        metrics = [[local.metric_ns, local.metric_name["feedback_up"]], [local.metric_ns, local.metric_name["feedback_down"]]]
      } },
      { type = "metric", x = 8, y = 8, width = 8, height = 6, properties = {
        title   = "Model tokens (per day)", region = var.aws_region, stat = "Sum", period = 86400, view = "bar"
        metrics = [[local.metric_ns, local.metric_name["chat_tokens"]], [local.metric_ns, local.metric_name["investigation_tokens"]]]
      } },
      { type = "metric", x = 16, y = 8, width = 8, height = 6, properties = {
        title   = "Weekly run: investigations and review", region = var.aws_region, stat = "Sum", period = 86400, view = "bar"
        metrics = [for k in ["investigations", "investigation_low", "investigation_failed", "review_pending"] : [local.metric_ns, local.metric_name[k]]]
      } },
      { type = "metric", x = 0, y = 14, width = 12, height = 6, properties = {
        title   = "Gateway tool calls / refusals", region = var.aws_region, stat = "Sum", period = 3600, view = "timeSeries"
        metrics = local.agentcore ? [[local.metric_ns, local.metric_name["gateway_tool_calls"]], [local.metric_ns, local.metric_name["gateway_tool_denied"]]] : [[local.metric_ns, local.metric_name["questions"]]]
      } },
      { type = "log", x = 12, y = 14, width = 12, height = 6, properties = {
        title = "Latest low-confidence answers", region = var.aws_region, view = "table"
        query = "SOURCE '${aws_cloudwatch_log_group.fn["chat"].name}' | filter event = 'chat' and low_confidence = 1 | fields @timestamp, user, confidence, retries, rounds | sort @timestamp desc | limit 20"
      } },
    ]
  })
}
