# PDRI Terraform Variables
# =========================

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "domain_name" {
  description = "Primary domain name for PDRI"
  type        = string
  default     = "pdri.example.com"
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID"
  type        = string
  default     = ""
}

variable "enable_eu_region" {
  description = "Enable EU-WEST-1 region deployment"
  type        = bool
  default     = true
}

variable "enable_apac_region" {
  description = "Enable AP-SOUTHEAST-1 region deployment"
  type        = bool
  default     = true
}

variable "enable_cloudfront" {
  description = "Enable CloudFront CDN"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Application = "PDRI"
    Owner       = "Platform Team"
  }
}
