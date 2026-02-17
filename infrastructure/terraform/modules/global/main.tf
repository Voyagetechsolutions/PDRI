# PDRI Global Module
# ==================
# Global resources: Route53, CloudFront

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================
variable "domain_name" {
  description = "Primary domain name"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "primary_region_alb_dns" {
  description = "Primary region ALB DNS"
  type        = string
}

variable "eu_region_alb_dns" {
  description = "EU region ALB DNS"
  type        = string
  default     = ""
}

variable "apac_region_alb_dns" {
  description = "APAC region ALB DNS"
  type        = string
  default     = ""
}

variable "enable_cloudfront" {
  description = "Enable CloudFront"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}

# =============================================================================
# Route53 Health Checks
# =============================================================================
resource "aws_route53_health_check" "primary" {
  fqdn              = var.primary_region_alb_dns
  port              = 443
  type              = "HTTPS"
  resource_path     = "/api/v2/health"
  failure_threshold = 3
  request_interval  = 30
  
  tags = merge(var.tags, {
    Name = "pdri-primary-health"
  })
}

resource "aws_route53_health_check" "eu" {
  count = var.eu_region_alb_dns != "" ? 1 : 0
  
  fqdn              = var.eu_region_alb_dns
  port              = 443
  type              = "HTTPS"
  resource_path     = "/api/v2/health"
  failure_threshold = 3
  request_interval  = 30
  
  tags = merge(var.tags, {
    Name = "pdri-eu-health"
  })
}

resource "aws_route53_health_check" "apac" {
  count = var.apac_region_alb_dns != "" ? 1 : 0
  
  fqdn              = var.apac_region_alb_dns
  port              = 443
  type              = "HTTPS"
  resource_path     = "/api/v2/health"
  failure_threshold = 3
  request_interval  = 30
  
  tags = merge(var.tags, {
    Name = "pdri-apac-health"
  })
}

# =============================================================================
# Route53 Records - Latency-based Routing
# =============================================================================
resource "aws_route53_record" "primary" {
  zone_id = var.hosted_zone_id
  name    = "api.${var.domain_name}"
  type    = "A"
  
  set_identifier = "primary-us-east-1"
  
  latency_routing_policy {
    region = "us-east-1"
  }
  
  alias {
    name                   = var.primary_region_alb_dns
    zone_id                = data.aws_lb_hosted_zone_id.main.id
    evaluate_target_health = true
  }
  
  health_check_id = aws_route53_health_check.primary.id
}

resource "aws_route53_record" "eu" {
  count = var.eu_region_alb_dns != "" ? 1 : 0
  
  zone_id = var.hosted_zone_id
  name    = "api.${var.domain_name}"
  type    = "A"
  
  set_identifier = "secondary-eu-west-1"
  
  latency_routing_policy {
    region = "eu-west-1"
  }
  
  alias {
    name                   = var.eu_region_alb_dns
    zone_id                = data.aws_lb_hosted_zone_id.eu.id
    evaluate_target_health = true
  }
  
  health_check_id = aws_route53_health_check.eu[0].id
}

resource "aws_route53_record" "apac" {
  count = var.apac_region_alb_dns != "" ? 1 : 0
  
  zone_id = var.hosted_zone_id
  name    = "api.${var.domain_name}"
  type    = "A"
  
  set_identifier = "secondary-ap-southeast-1"
  
  latency_routing_policy {
    region = "ap-southeast-1"
  }
  
  alias {
    name                   = var.apac_region_alb_dns
    zone_id                = data.aws_lb_hosted_zone_id.apac.id
    evaluate_target_health = true
  }
  
  health_check_id = aws_route53_health_check.apac[0].id
}

# =============================================================================
# Data Sources
# =============================================================================
data "aws_lb_hosted_zone_id" "main" {
  region = "us-east-1"
}

data "aws_lb_hosted_zone_id" "eu" {
  region = "eu-west-1"
}

data "aws_lb_hosted_zone_id" "apac" {
  region = "ap-southeast-1"
}

# =============================================================================
# CloudFront Distribution
# =============================================================================
resource "aws_cloudfront_distribution" "pdri" {
  count = var.enable_cloudfront ? 1 : 0
  
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "PDRI Global Distribution"
  default_root_object = ""
  price_class         = "PriceClass_All"
  
  aliases = ["${var.domain_name}"]
  
  # Primary Origin
  origin {
    domain_name = "api.${var.domain_name}"
    origin_id   = "pdri-api"
    
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
  
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "pdri-api"
    
    forwarded_values {
      query_string = true
      headers      = ["Authorization", "Host", "Origin"]
      
      cookies {
        forward = "all"
      }
    }
    
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
  }
  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.pdri.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
  
  tags = var.tags
}

# =============================================================================
# ACM Certificate
# =============================================================================
resource "aws_acm_certificate" "pdri" {
  domain_name       = var.domain_name
  validation_method = "DNS"
  
  subject_alternative_names = [
    "*.${var.domain_name}"
  ]
  
  lifecycle {
    create_before_destroy = true
  }
  
  tags = var.tags
}

# =============================================================================
# Outputs
# =============================================================================
output "api_endpoint" {
  value = "https://api.${var.domain_name}"
}

output "cloudfront_domain" {
  value = var.enable_cloudfront ? aws_cloudfront_distribution.pdri[0].domain_name : null
}

output "cloudfront_distribution_id" {
  value = var.enable_cloudfront ? aws_cloudfront_distribution.pdri[0].id : null
}
