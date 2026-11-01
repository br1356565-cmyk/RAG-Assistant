resource "aws_db_subnet_group" "db" {
  name       = local.name
  subnet_ids = local.private_subnet_ids
}

resource "aws_db_parameter_group" "db" {
  name   = "${local.name}-pg${split(".", var.db_engine_version)[0]}"
  family = "postgres${split(".", var.db_engine_version)[0]}"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "db" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = "audit"
  username = "audit_master"
  # RDS creates and rotates the master password in Secrets Manager; it never enters state.
  manage_master_user_password = true
  # Lambdas connect with short-lived IAM tokens, not passwords.
  iam_database_authentication_enabled = true

  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.db.name
  publicly_accessible    = false
  multi_az               = var.db_multi_az

  backup_retention_period    = 7
  copy_tags_to_snapshot      = true
  auto_minor_version_upgrade = true
  deletion_protection        = var.db_deletion_protection
  skip_final_snapshot        = var.db_skip_final_snapshot
  final_snapshot_identifier  = var.db_skip_final_snapshot ? null : "${local.name}-final"
}
