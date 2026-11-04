resource "aws_s3_bucket" "this" {
  bucket = var.name
  tags   = merge(var.tags, { team = var.team })
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = var.expire_days == null ? 0 : 1
  bucket = aws_s3_bucket.this.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.expire_days
    }
  }
}
