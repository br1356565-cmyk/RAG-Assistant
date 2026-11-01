# ── Raw collector output (one JSON file per collector per run) ───────────────
resource "aws_s3_bucket" "data" {
  bucket        = "${local.name}-data-${local.account_id}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "expire-raw-runs"
    status = "Enabled"
    filter {
      prefix = "runs/"
    }
    expiration {
      days = var.raw_retention_days
    }
  }
}

# ── Web app (private; served only through CloudFront) ────────────────────────
resource "aws_s3_bucket" "web" {
  bucket        = "${local.name}-web-${local.account_id}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_public_access_block" "web" {
  bucket                  = aws_s3_bucket.web.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "web" {
  bucket = aws_s3_bucket.web.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "web_bucket" {
  statement {
    sid       = "CloudFrontReadOnly"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.web.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.web.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "web" {
  bucket = aws_s3_bucket.web.id
  policy = data.aws_iam_policy_document.web_bucket.json
}

resource "aws_s3_object" "web_files" {
  for_each = {
    "index.html" = "text/html; charset=utf-8"
    "app.js"     = "application/javascript; charset=utf-8"
  }
  bucket        = aws_s3_bucket.web.id
  key           = each.key
  source        = "${local.repo_root}/web/${each.key}"
  etag          = filemd5("${local.repo_root}/web/${each.key}")
  content_type  = each.value
  cache_control = "no-cache"
}

resource "aws_s3_object" "web_config" {
  bucket = aws_s3_bucket.web.id
  key    = "config.js"
  content = templatefile("${local.repo_root}/web/config.js.tftpl", {
    tenant_id = var.entra_tenant_id
    client_id = var.entra_client_id
    api_scope = local.api_scope
  })
  content_type  = "application/javascript; charset=utf-8"
  cache_control = "no-cache"
}
