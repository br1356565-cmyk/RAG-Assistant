# Optional network for a fresh account (create_vpc = true):
#   two private subnets (Lambdas + RDS, which needs two AZs), one public subnet for the NAT,
#   and either a NAT instance (cheap, demo) or a managed NAT gateway.
# Nothing here is created when create_vpc = false.

data "aws_availability_zones" "available" {
  count = var.create_vpc ? 1 : 0
  state = "available"
}

locals {
  azs      = var.create_vpc ? slice(data.aws_availability_zones.available[0].names, 0, 2) : []
  nat_inst = var.create_vpc && var.nat_mode == "instance"
  nat_gw   = var.create_vpc && var.nat_mode == "gateway"
}

resource "aws_vpc" "main" {
  count                = var.create_vpc ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_subnet" "private" {
  count             = var.create_vpc ? 2 : 0
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.name}-private-${count.index}" }
}

resource "aws_subnet" "public" {
  count                   = var.create_vpc ? 1 : 0
  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, 15)
  availability_zone       = local.azs[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-public" }
}

resource "aws_internet_gateway" "main" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id
}

resource "aws_route_table" "public" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }
  tags = { Name = "${local.name}-public" }
}

resource "aws_route_table_association" "public" {
  count          = var.create_vpc ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id
  tags   = { Name = "${local.name}-private" }
}

resource "aws_route_table_association" "private" {
  count          = var.create_vpc ? 2 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# ── NAT gateway (managed) ────────────────────────────────────────────────────
resource "aws_eip" "nat" {
  count  = local.nat_gw ? 1 : 0
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  count         = local.nat_gw ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route" "private_via_gateway" {
  count                  = local.nat_gw ? 1 : 0
  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[0].id
}

# ── NAT instance (demo) ──────────────────────────────────────────────────────
# Amazon Linux 2023 on t4g.nano with IP forwarding and masquerade. No SSH key and no
# inbound access from the internet; only the VPC can send traffic through it.
# If it stops, Lambdas lose internet access (RDS still works); `terraform apply` restores it.
data "aws_ssm_parameter" "al2023_arm" {
  count = local.nat_inst ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_security_group" "nat" {
  count       = local.nat_inst ? 1 : 0
  name        = "${local.name}-nat"
  description = "NAT instance: forwards traffic from the VPC only"
  vpc_id      = aws_vpc.main[0].id
}

resource "aws_vpc_security_group_ingress_rule" "nat_from_vpc" {
  count             = local.nat_inst ? 1 : 0
  security_group_id = aws_security_group.nat[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = var.vpc_cidr
  description       = "Traffic from the private subnets"
}

resource "aws_vpc_security_group_egress_rule" "nat_out" {
  count             = local.nat_inst ? 1 : 0
  security_group_id = aws_security_group.nat[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "To the internet"
}

resource "aws_instance" "nat" {
  count                       = local.nat_inst ? 1 : 0
  ami                         = data.aws_ssm_parameter.al2023_arm[0].value
  instance_type               = "t4g.nano"
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.nat[0].id]
  associate_public_ip_address = true
  source_dest_check           = false

  metadata_options {
    http_tokens = "required"
  }

  user_data_replace_on_change = true
  user_data                   = <<-EOT
    #!/bin/bash
    set -euxo pipefail
    dnf install -y iptables-services
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/90-nat.conf
    sysctl --system
    IFACE=$(ip route show default | awk '{print $5; exit}')
    iptables -t nat -A POSTROUTING -o "$IFACE" -s ${var.vpc_cidr} -j MASQUERADE
    iptables -F FORWARD
    iptables-save > /etc/sysconfig/iptables   # replaces the package default, which rejects forwarding
    systemctl enable --now iptables
  EOT

  # AMI updates shouldn't replace a working NAT on every apply.
  lifecycle {
    ignore_changes = [ami]
  }

  tags       = { Name = "${local.name}-nat" }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_route" "private_via_instance" {
  count                  = local.nat_inst ? 1 : 0
  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat[0].primary_network_interface_id
}
