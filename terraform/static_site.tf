# =============================================================================
# CloudWatchDog — Static Documentation Site
# S3 + CloudFront + ACM + Route53 for https://awsjourney.space
# =============================================================================

# ---------------------------------------------------------------------------
# Secondary provider in us-east-1 (required for CloudFront ACM certificates)
# ---------------------------------------------------------------------------

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = merge(
      {
        Project     = var.project_name
        Environment = var.environment
        ManagedBy   = "Terraform"
        Purpose     = "DocumentationSite"
      },
      var.tags,
    )
  }
}

# ---------------------------------------------------------------------------
# Route53 — Hosted Zone Data Source
# ---------------------------------------------------------------------------

data "aws_route53_zone" "main" {
  zone_id = var.route53_zone_id
}

# ---------------------------------------------------------------------------
# ACM Certificate — HTTPS (Must use us_east_1 provider for CloudFront)
# ---------------------------------------------------------------------------

resource "aws_acm_certificate" "docs_cert" {
  provider                  = aws.us_east_1
  domain_name               = var.domain_name
  subject_alternative_names = ["www.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.docs_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

resource "aws_acm_certificate_validation" "docs_cert" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.docs_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# ---------------------------------------------------------------------------
# S3 Bucket — Static Site Hosting
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "docs_site" {
  bucket        = "awsjourney-space-docs-paras"
  force_destroy = true
}

resource "aws_s3_bucket_website_configuration" "docs_site" {
  bucket = aws_s3_bucket.docs_site.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "/error.html"
  }
}

resource "aws_s3_bucket_public_access_block" "docs_site" {
  bucket = aws_s3_bucket.docs_site.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# CloudFront Origin Access Control (OAC) — Secure S3 access
# ---------------------------------------------------------------------------

resource "aws_cloudfront_origin_access_control" "docs_oac" {
  name                              = "${var.project_name}-docs-oac"
  description                       = "OAC for CloudWatchDog documentation site"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ---------------------------------------------------------------------------
# S3 Bucket Policy — Allow CloudFront OAC access only
# ---------------------------------------------------------------------------

resource "aws_s3_bucket_policy" "docs_site" {
  bucket = aws_s3_bucket.docs_site.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontOAC"
        Effect    = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.docs_site.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.docs_site.arn
          }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# CloudFront Distribution
# ---------------------------------------------------------------------------

resource "aws_cloudfront_distribution" "docs_site" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  aliases             = [var.domain_name, "www.${var.domain_name}"]
  comment             = "CloudWatchDog documentation site — ${var.domain_name}"
  price_class         = "PriceClass_100"
  wait_for_deployment = true

  origin {
    domain_name              = aws_s3_bucket.docs_site.bucket_regional_domain_name
    origin_id                = "S3-${var.domain_name}"
    origin_access_control_id = aws_cloudfront_origin_access_control.docs_oac.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.domain_name}"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  custom_error_response {
    error_code            = 403
    response_code         = 404
    response_page_path    = "/error.html"
    error_caching_min_ttl = 60
  }

  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/error.html"
    error_caching_min_ttl = 60
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.docs_cert.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  depends_on = [
    aws_acm_certificate_validation.docs_cert,
  ]
}

# ---------------------------------------------------------------------------
# Route53 DNS Records — Point domain to CloudFront
# ---------------------------------------------------------------------------

resource "aws_route53_record" "docs_a" {
  allow_overwrite = true
  zone_id         = data.aws_route53_zone.main.zone_id
  name            = var.domain_name
  type            = "A"

  alias {
    name                   = aws_cloudfront_distribution.docs_site.domain_name
    zone_id                = aws_cloudfront_distribution.docs_site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "docs_aaaa" {
  allow_overwrite = true
  zone_id         = data.aws_route53_zone.main.zone_id
  name            = var.domain_name
  type            = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.docs_site.domain_name
    zone_id                = aws_cloudfront_distribution.docs_site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "docs_www" {
  allow_overwrite = true
  zone_id         = data.aws_route53_zone.main.zone_id
  name            = "www.${var.domain_name}"
  type            = "A"

  alias {
    name                   = aws_cloudfront_distribution.docs_site.domain_name
    zone_id                = aws_cloudfront_distribution.docs_site.hosted_zone_id
    evaluate_target_health = false
  }
}