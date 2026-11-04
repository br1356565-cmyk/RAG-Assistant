resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-dlq"
  message_retention_seconds = 1209600
  tags                      = merge(var.tags, { team = var.team })
}

resource "aws_sqs_queue" "this" {
  name                       = var.name
  message_retention_seconds  = var.retention_days * 86400
  visibility_timeout_seconds = var.visibility_timeout_seconds
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = var.max_receive_count
  })
  tags = merge(var.tags, { team = var.team })
}
