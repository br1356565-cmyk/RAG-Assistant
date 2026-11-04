# Read-only server diagnostics through SSM Run Command. The agent never gets a shell: it
# chooses one check from a fixed menu, and this document holds the only commands that can
# run. Parameters are validated by SSM (allowedValues / allowedPattern) before anything runs,
# and service and log names are matched against fixed lists inside the script as well.
# IAM (agentcore.tf) allows SendCommand only with this document, and only on instances
# tagged agent-diagnostics=allowed; the tool additionally requires team=<caller's team>.

locals {
  diag_service_cases = join("\n", [for s in var.diagnostic_services :
  "      ${s}) systemctl status --no-pager --lines=20 '${s}' 2>&1 | head -60 ;;"])
  diag_log_cases = join("\n", [for name, path in var.diagnostic_logs :
    path == "journal"
    ? "      ${name}) journalctl --no-pager -n 100 -o short-iso 2>&1 | tail -100 ;;"
  : "      ${name}) tail -n 100 '${path}' 2>&1 ;;"])

  diag_script = <<-EOT
    set -u
    CHECK='{{ check }}'
    TARGET='{{ target }}'
    case "$CHECK" in
      disk_usage)      df -h -x tmpfs -x devtmpfs -x squashfs ;;
      memory)          free -m; echo; head -5 /proc/meminfo ;;
      top_processes)   ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu | head -15 ;;
      listening_ports) ss -tlnp 2>/dev/null || netstat -tlnp ;;
      uptime)          uptime; cat /proc/loadavg ;;
      service_status)
        case "$TARGET" in
    ${local.diag_service_cases}
          *) echo "service not allowed: $TARGET"; exit 2 ;;
        esac ;;
      recent_logs)
        case "$TARGET" in
    ${local.diag_log_cases}
          *) echo "log not allowed: $TARGET"; exit 2 ;;
        esac ;;
      *) echo "unknown check"; exit 2 ;;
    esac
  EOT
}

resource "aws_ssm_document" "diagnostics" {
  count           = var.diagnostics_enabled ? 1 : 0
  name            = "${local.name}-diagnostics"
  document_type   = "Command"
  document_format = "JSON"
  target_type     = "/AWS::EC2::Instance"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "DevOps audit agent: one read-only diagnostic check"
    parameters = {
      check = {
        type          = "String"
        description   = "Which check to run"
        allowedValues = ["disk_usage", "memory", "top_processes", "listening_ports", "service_status", "recent_logs", "uptime"]
      }
      target = {
        type           = "String"
        description    = "Service or log name (service_status, recent_logs); 'none' otherwise"
        default        = "none"
        allowedPattern = "^[A-Za-z0-9_.@-]{1,64}$"
      }
    }
    mainSteps = [{
      action       = "aws:runShellScript"
      name         = "check"
      precondition = { StringEquals = ["platformType", "Linux"] }
      inputs       = { runCommand = split("\n", trimspace(local.diag_script)), timeoutSeconds = "25" }
    }]
  })
}

# ── Optional demo instance to try the checks on ─────────────────────────────────────────
data "aws_ssm_parameter" "diag_ami" {
  count = var.diagnostics_enabled && var.diagnostics_demo_instance ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_iam_role" "diag_instance" {
  count = var.diagnostics_enabled && var.diagnostics_demo_instance ? 1 : 0
  name  = "${local.name}-diag-instance"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "diag_instance_ssm" {
  count      = var.diagnostics_enabled && var.diagnostics_demo_instance ? 1 : 0
  role       = aws_iam_role.diag_instance[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "diag_instance" {
  count = var.diagnostics_enabled && var.diagnostics_demo_instance ? 1 : 0
  name  = "${local.name}-diag-instance"
  role  = aws_iam_role.diag_instance[0].name
}

resource "aws_security_group" "diag_instance" {
  count       = var.diagnostics_enabled && var.diagnostics_demo_instance ? 1 : 0
  name        = "${local.name}-diag-instance"
  description = "Demo diagnostics instance: no inbound; outbound for the SSM agent"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "diag_instance" {
  count             = var.diagnostics_enabled && var.diagnostics_demo_instance ? 1 : 0
  security_group_id = aws_security_group.diag_instance[0].id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
  description       = "SSM, EC2 messages and package repos over HTTPS (via NAT)"
}

resource "aws_instance" "diag_demo" {
  count                  = var.diagnostics_enabled && var.diagnostics_demo_instance ? 1 : 0
  ami                    = data.aws_ssm_parameter.diag_ami[0].value
  instance_type          = var.diagnostics_demo_instance_type
  subnet_id              = local.private_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.diag_instance[0].id]
  iam_instance_profile   = aws_iam_instance_profile.diag_instance[0].name

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = 8
    encrypted   = true
  }

  # A web server and its error log, so service_status and recent_logs have something to show.
  user_data = <<-EOT
    #!/bin/bash
    dnf install -y nginx && systemctl enable --now nginx
  EOT

  tags = {
    Name                = "${local.name}-diag-demo"
    "agent-diagnostics" = "allowed"
    team                = var.diagnostics_demo_team
  }

  lifecycle {
    ignore_changes = [ami]
    precondition {
      condition     = var.diagnostics_demo_team != null
      error_message = "Set diagnostics_demo_team to the team id that owns the demo instance."
    }
  }
}
