# CloudFront serves the web app from S3 and forwards /api/* to the chat function URL.
# Both origins use origin access control: S3 and the function URL accept only CloudFront.

resource "aws_lambda_function_url" "chat" {
  function_name      = aws_lambda_function.fn["chat"].function_name
  qualifier          = aws_lambda_alias.live["chat"].name
  authorization_type = "AWS_IAM"
  invoke_mode        = "BUFFERED"
}

resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "${local.name}-s3"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_origin_access_control" "lambda" {
  name                              = "${local.name}-lambda"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

data "aws_cloudfront_response_headers_policy" "security" {
  name = "Managed-SecurityHeadersPolicy"
}

resource "aws_cloudfront_distribution" "web" {
  enabled             = true
  comment             = "DevOps audit assistant"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  web_acl_id          = length(var.allowed_cidrs) > 0 ? aws_wafv2_web_acl.web[0].arn : null

  origin {
    origin_id                = "web"
    domain_name              = aws_s3_bucket.web.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  origin {
    origin_id                = "chat"
    domain_name              = split("/", aws_lambda_function_url.chat.function_url)[2]
    origin_access_control_id = aws_cloudfront_origin_access_control.lambda.id
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 60 # chat answers can take a while; raise via an AWS quota for longer
    }
  }

  # The site is a few small files for an internal audience: no edge caching, so deploys show immediately.
  default_cache_behavior {
    target_origin_id           = "web"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security.id
    compress                   = true
  }

  ordered_cache_behavior {
    path_pattern               = "/api/*"
    target_origin_id           = "chat"
    viewer_protocol_policy     = "https-only"
    allowed_methods            = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# CloudFront may call the chat function URL, and nothing else may.
resource "aws_lambda_permission" "cloudfront_url" {
  statement_id           = "AllowCloudFrontFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  principal              = "cloudfront.amazonaws.com"
  function_name          = aws_lambda_function.fn["chat"].function_name
  qualifier              = aws_lambda_alias.live["chat"].name
  function_url_auth_type = "AWS_IAM"
  source_arn             = aws_cloudfront_distribution.web.arn
}

resource "aws_lambda_permission" "cloudfront_invoke" {
  statement_id  = "AllowCloudFrontInvoke"
  action        = "lambda:InvokeFunction"
  principal     = "cloudfront.amazonaws.com"
  function_name = aws_lambda_function.fn["chat"].function_name
  qualifier     = aws_lambda_alias.live["chat"].name
  source_arn    = aws_cloudfront_distribution.web.arn
}

# ── Optional IP allowlist (office/VPN) ─────────────────────────────────────
resource "aws_wafv2_ip_set" "allowed" {
  count              = length(var.allowed_cidrs) > 0 ? 1 : 0
  provider           = aws.us_east_1
  name               = "${local.name}-allowed"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.allowed_cidrs
}

resource "aws_wafv2_web_acl" "web" {
  count    = length(var.allowed_cidrs) > 0 ? 1 : 0
  provider = aws.us_east_1
  name     = "${local.name}-web"
  scope    = "CLOUDFRONT"

  default_action {
    block {}
  }

  rule {
    name     = "allow-office-and-vpn"
    priority = 1
    action {
      allow {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allowed[0].arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-allowed"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-web"
    sampled_requests_enabled   = true
  }
}
