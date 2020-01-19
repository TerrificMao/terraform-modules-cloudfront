# Configure AWS Provider
provider "aws" {
  alias = "this"
}

# Variables
variable project {
  type = dex
  description = "project"
}

variable env {
  type = pre
  description = "environment"
}

variable cfcalltag {
  type = string
  description = "cfcalltag"
}

variable web_dispatcher_alb_dns_name {
  type = string
  description = "Web Dispatcher ALB"
}

variable s3_cloudfront_errorpages_bucket_name {
  type = string
  description = "Cloudfront ErrorPages Bucket Name"
}

variable acm_certificate_arn {
  type = string
  description = "ACM ARN"
}

variable cloudfront_log_buket_name {
  type = string
  description = "Cloudfront Logs Bucket"
}

variable web_acl_id {
  type = string
  description = "WAF Web ACL ID"
}

#======================================================================================
# Configure Cloudfront
#======================================================================================
resource "aws_cloudfront_distribution" "web-cloudfront" {
  provider    = aws.this
  # Distribution Settings
  price_class = "PriceClass_All"
  web_acl_id  = "${var.web_acl_id}"
  aliases     = ["preprod.example.com"] 
  viewer_certificate {
    acm_certificate_arn = "${var.acm_certificate_arn}"

    # One of SSLv3, TLSv1, TLSv1_2016, TLSv1.1_2016 or TLSv1.2_2018. Default: TLSv1.
    # minimum_protocol_version      = var.viewer_minimum_protocol_version
    # Security Policy
    minimum_protocol_version = "TLSv1"
    # vip/sni-only. vip causes CloudFront to use a dedicated IP address and may incur extra charges.
    ssl_support_method       = "vip"
  }
  logging_config {
    include_cookies = false
    bucket = "${var.cloudfront_log_buket_name}.s3.amazonaws.com"
    prefix = "webprod/cflogs/"
  }
  is_ipv6_enabled = false
  comment         = "TF preprod.example.com"
  enabled         = true
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  # cf custom error response
  custom_error_response {
    error_caching_min_ttl = 0
    error_code            = 404
  }

#======================================================================================
# ALB Origin Settings
#======================================================================================
  origin {
    #domain_name = "${aws_lb.dispatcher_alb.dns_name}"
    #origin_id   = "ELB-${var.project}-${var.env}-dispatcher-alb"
    domain_name  = "${var.web_dispatcher_alb_dns_name}"
    origin_id    = "ELB-${var.project}-${var.env}-dispatcher-alb"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "match-viewer"
      origin_ssl_protocols   = ["TLSv1", "TLSv1.1", "TLSv1.2"]

      #origin_ssl_protocols    = "TLSv1"
      origin_keepalive_timeout = 5
      origin_read_timeout      = 30
    }
    custom_header {
      name  = "x-cfcalltag"
      value = var.x-cfcalltag
    }
  }

#======================================================================================
# S3 Origin Settings. If an S3 origin is required, use s3_origin_config instead.
#====================================================================================== 
  origin {
    domain_name = "${var.s3_cloudfront_errorpages_bucket_name}.s3.amazonaws.com"
    origin_id   = "S3-${var.s3_cloudfront_errorpages_bucket_name}"
    s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
    }
  }

  # default Cache Behavior Settings
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]

    # 用 target_origin_id 决定使用哪个源站
    target_origin_id = "ELB-${var.project}-${var.env}-dispatcher-alb"

    # 默认behavior要把所有开关都打开
    forwarded_values {
      query_string = true
      cookies {
        forward    = "all"
      }
      headers      = ["*"]
    }
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    compress               = false
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/.well-known*"
    allowed_methods  = ["GET", "HEAD",]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${var.s3_cloudfront_errorpages_bucket_name}"
    forwarded_values{
      query_string   = false
      cookies {
        forward      = "none"
      }
    }
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/??/futures/*"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ELB-${var.project}-${var.env}-dispatcher-alb"
    forwarded_values {
      headers        = ["Host", "CloudFront-Is-Mobile-Viewer","CloudFront-Viewer-Country"]
      cookies {
        #forward = "all"
        forward            = "whitelist" 
        whitelisted_names  = ["canary"]
      }
      query_string         = true
    }
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = false
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 2
  ordered_cache_behavior {
    path_pattern     = "/??/trade/*"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ELB-${var.project}-${var.env}-dispatcher-alb"
    forwarded_values {
      headers        = ["Host", "CloudFront-Is-Mobile-Viewer"]
      cookies {
        #forward = "all"
        forward            = "whitelist" 
        whitelisted_names  = ["canary"]
      }
      query_string         = true
    }
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = false
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 3
  ordered_cache_behavior {
    path_pattern     = "/??/"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ELB-${var.project}-${var.env}-dispatcher-alb"
    forwarded_values {
      headers        = ["Host", "CloudFront-Is-Mobile-Viewer"]
      cookies {
        #forward = "all"
        forward            = "whitelist" 
        whitelisted_names  = ["canary"]
      }
      query_string         = true
    }
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = false
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 4
  ordered_cache_behavior {
    path_pattern     = "/??/*"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ELB-${var.project}-${var.env}-dispatcher-alb"
    forwarded_values {
      headers        = ["Host", "CloudFront-Is-Mobile-Viewer"]
      cookies {
        #forward = "all"
        forward            = "whitelist" 
        whitelisted_names  = ["canary"]
      }
      query_string         = true
    }
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = false
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 5 (no query string)
  ordered_cache_behavior {
    path_pattern     = "/.../product/currency"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ELB-${var.project}-${var.env}-dispatcher-alb"
    forwarded_values {
      headers        = ["Host"]
      cookies {
        forward      = "none"
      }
      query_string   = false
    }
    min_ttl                = 600
    default_ttl            = 600
    max_ttl                = 600
    compress               = false
    viewer_protocol_policy = "redirect-to-https"
  }

  tags = {
    env     = var.env
    project = var.project
  }
}

# CloudFront OAI Setting
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  provider    = aws.this
  comment     = "aws_cloudfront_origin_access_identity"
}
data "aws_iam_policy_document" "s3_policy" {
  provider    = aws.this
  statement {
    sid       = "S3GetObjectForCloudFront"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.s3_cloudfront_errorpages_bucket_name}/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}","arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E21PJ3US1O7KFT"]
    }
  }
}
resource "aws_s3_bucket_policy" "s3_cloudfront_errorpages_bucket_policy" {
  providers      = {
    aws.this     = aws.dex-pre
  }
  bucket = "${var.s3_cloudfront_errorpages_bucket_name}"
  policy = "${data.aws_iam_policy_document.s3_policy.json}"
}

# output configuration
# output "cf_id" {
#   value       = "${aws_cloudfront_distribution.web-cloudfront.id}"
#   description = "ID of AWS CloudFront distribution"
# }

output "cf_arn" {
  value       = "${aws_cloudfront_distribution.web-cloudfront.arn}"
  description = "ID of AWS CloudFront distribution"
}

output "cf_status" {
  value       = "${aws_cloudfront_distribution.web-cloudfront.status}"
  description = "Current status of the distribution"
}

output "cf_domain_name" {
  value       = "${aws_cloudfront_distribution.web-cloudfront.domain_name}"
  description = "Domain name corresponding to the distribution"
}

output "cf_aliases_domain" {
  value = "${aws_cloudfront_distribution.web-cloudfront.aliases}"
}

output "cf_etag" {
  value       = "${aws_cloudfront_distribution.web-cloudfront.etag}"
  description = "Current version of the distribution's information"
}
