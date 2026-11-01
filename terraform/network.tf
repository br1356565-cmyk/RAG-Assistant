locals {
  vpc_id                  = var.create_vpc ? aws_vpc.main[0].id : var.vpc_id
  private_subnet_ids      = var.create_vpc ? aws_subnet.private[*].id : var.private_subnet_ids
  private_route_table_ids = var.create_vpc ? [aws_route_table.private[0].id] : var.private_route_table_ids
}

resource "aws_security_group" "lambda" {
  name        = "${local.name}-lambda"
  description = "DevOps audit Lambdas in the VPC"
  vpc_id      = local.vpc_id

  lifecycle {
    precondition {
      condition     = var.create_vpc || (var.vpc_id != null && length(var.private_subnet_ids) >= 2)
      error_message = "Set create_vpc = true, or give vpc_id and at least two private_subnet_ids (RDS needs two AZs)."
    }
    precondition {
      condition     = var.llm_backend != "gateway" || var.gateway_url != null
      error_message = "llm_backend = \"gateway\" needs gateway_url."
    }
  }
}

resource "aws_vpc_security_group_egress_rule" "lambda_all" {
  security_group_id = aws_security_group.lambda.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "RDS, model endpoint, GitHub and AWS APIs via NAT"
}

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "DevOps audit PostgreSQL"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_lambda" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.lambda.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Audit Lambdas"
}

resource "aws_vpc_security_group_ingress_rule" "gateway_from_lambda" {
  count                        = var.gateway_security_group_id == null ? 0 : 1
  security_group_id            = var.gateway_security_group_id
  referenced_security_group_id = aws_security_group.lambda.id
  ip_protocol                  = "tcp"
  from_port                    = var.gateway_port
  to_port                      = var.gateway_port
  description                  = "DevOps audit Lambdas to LiteLLM"
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.create_vpc || length(var.private_route_table_ids) > 0 ? 1 : 0
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.private_route_table_ids
}
