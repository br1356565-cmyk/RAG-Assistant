# Optional spend guard (monthly_budget_usd + alarm_email). Budgets report on the whole
# account, so in a shared account this covers more than this stack.

resource "aws_budgets_budget" "monthly" {
  count        = var.monthly_budget_usd == null ? 0 : 1
  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = { for n in [
      { type = "ACTUAL", pct = 50 },
      { type = "ACTUAL", pct = 80 },
      { type = "ACTUAL", pct = 100 },
      { type = "FORECASTED", pct = 100 },
    ] : "${n.type}-${n.pct}" => n }
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.pct
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.alarm_email]
    }
  }

  lifecycle {
    precondition {
      condition     = var.alarm_email != null
      error_message = "monthly_budget_usd needs alarm_email to send the notifications to."
    }
  }
}
