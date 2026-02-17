# PDRI Multi-Region Terraform Configuration
# ==========================================
# Main entry point for AWS infrastructure

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
  
  backend "s3" {
    bucket         = "pdri-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "pdri-terraform-locks"
  }
}

# =============================================================================
# Provider Configuration - US-EAST-1 (Primary)
# =============================================================================
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  
  default_tags {
    tags = {
      Project     = "PDRI"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# =============================================================================
# Provider Configuration - EU-WEST-1
# =============================================================================
provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
  
  default_tags {
    tags = {
      Project     = "PDRI"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# =============================================================================
# Provider Configuration - AP-SOUTHEAST-1
# =============================================================================
provider "aws" {
  alias  = "ap_southeast_1"
  region = "ap-southeast-1"
  
  default_tags {
    tags = {
      Project     = "PDRI"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# =============================================================================
# US-EAST-1 Region (Primary)
# =============================================================================
module "us_east_1" {
  source = "./modules/region"
  
  providers = {
    aws = aws.us_east_1
  }
  
  region            = "us-east-1"
  region_role       = "primary"
  vpc_cidr          = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  
  eks_cluster_name  = "pdri-${var.environment}-us-east-1"
  eks_node_count    = var.environment == "prod" ? 5 : 2
  eks_node_type     = var.environment == "prod" ? "m5.xlarge" : "t3.large"
  
  neo4j_instance_type = var.environment == "prod" ? "r5.large" : "t3.medium"
  rds_instance_type   = var.environment == "prod" ? "db.r5.large" : "db.t3.medium"
  kafka_broker_count  = var.environment == "prod" ? 3 : 1
  
  enable_sagemaker = true
  
  tags = var.tags
}

# =============================================================================
# EU-WEST-1 Region
# =============================================================================
module "eu_west_1" {
  source = "./modules/region"
  
  providers = {
    aws = aws.eu_west_1
  }
  
  region            = "eu-west-1"
  region_role       = "secondary"
  vpc_cidr          = "10.1.0.0/16"
  availability_zones = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  
  eks_cluster_name  = "pdri-${var.environment}-eu-west-1"
  eks_node_count    = var.environment == "prod" ? 3 : 1
  eks_node_type     = var.environment == "prod" ? "m5.large" : "t3.medium"
  
  neo4j_instance_type = var.environment == "prod" ? "r5.large" : "t3.medium"
  rds_instance_type   = var.environment == "prod" ? "db.r5.large" : "db.t3.medium"
  kafka_broker_count  = var.environment == "prod" ? 3 : 1
  
  enable_sagemaker = false
  
  tags = var.tags
  
  count = var.enable_eu_region ? 1 : 0
}

# =============================================================================
# AP-SOUTHEAST-1 Region
# =============================================================================
module "ap_southeast_1" {
  source = "./modules/region"
  
  providers = {
    aws = aws.ap_southeast_1
  }
  
  region            = "ap-southeast-1"
  region_role       = "secondary"
  vpc_cidr          = "10.2.0.0/16"
  availability_zones = ["ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"]
  
  eks_cluster_name  = "pdri-${var.environment}-ap-southeast-1"
  eks_node_count    = var.environment == "prod" ? 3 : 1
  eks_node_type     = var.environment == "prod" ? "m5.large" : "t3.medium"
  
  neo4j_instance_type = var.environment == "prod" ? "r5.large" : "t3.medium"
  rds_instance_type   = var.environment == "prod" ? "db.r5.large" : "db.t3.medium"
  kafka_broker_count  = var.environment == "prod" ? 3 : 1
  
  enable_sagemaker = false
  
  tags = var.tags
  
  count = var.enable_apac_region ? 1 : 0
}

# =============================================================================
# Global Resources
# =============================================================================
module "global" {
  source = "./modules/global"
  
  providers = {
    aws = aws.us_east_1
  }
  
  domain_name     = var.domain_name
  hosted_zone_id  = var.hosted_zone_id
  environment     = var.environment
  
  primary_region_alb_dns = module.us_east_1.alb_dns_name
  eu_region_alb_dns      = var.enable_eu_region ? module.eu_west_1[0].alb_dns_name : ""
  apac_region_alb_dns    = var.enable_apac_region ? module.ap_southeast_1[0].alb_dns_name : ""
  
  enable_cloudfront = var.enable_cloudfront
  
  tags = var.tags
}

# =============================================================================
# Outputs
# =============================================================================
output "primary_cluster_endpoint" {
  description = "Primary EKS cluster endpoint"
  value       = module.us_east_1.eks_cluster_endpoint
}

output "primary_alb_dns" {
  description = "Primary region ALB DNS name"
  value       = module.us_east_1.alb_dns_name
}

output "global_endpoint" {
  description = "Global API endpoint"
  value       = module.global.api_endpoint
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain"
  value       = var.enable_cloudfront ? module.global.cloudfront_domain : null
}
