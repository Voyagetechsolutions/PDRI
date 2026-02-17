# PDRI Regional Module
# ====================
# Deploys infrastructure for a single AWS region

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
variable "region" {
  description = "AWS region"
  type        = string
}

variable "region_role" {
  description = "Role of this region (primary, secondary, dr)"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "availability_zones" {
  description = "Availability zones to use"
  type        = list(string)
}

variable "eks_cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "eks_node_count" {
  description = "Number of EKS worker nodes"
  type        = number
  default     = 3
}

variable "eks_node_type" {
  description = "EC2 instance type for EKS nodes"
  type        = string
  default     = "m5.large"
}

variable "neo4j_instance_type" {
  description = "Instance type for Neo4j"
  type        = string
  default     = "r5.large"
}

variable "rds_instance_type" {
  description = "Instance type for RDS"
  type        = string
  default     = "db.r5.large"
}

variable "kafka_broker_count" {
  description = "Number of MSK brokers"
  type        = number
  default     = 3
}

variable "enable_sagemaker" {
  description = "Enable SageMaker for ML"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}

# =============================================================================
# VPC
# =============================================================================
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "pdri-${var.region}"
  cidr = var.vpc_cidr
  
  azs             = var.availability_zones
  private_subnets = [for i, az in var.availability_zones : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i, az in var.availability_zones : cidrsubnet(var.vpc_cidr, 4, i + 8)]
  
  enable_nat_gateway     = true
  single_nat_gateway     = var.region_role != "primary"
  enable_dns_hostnames   = true
  enable_dns_support     = true
  
  tags = merge(var.tags, {
    Region = var.region
  })
}

# =============================================================================
# EKS Cluster
# =============================================================================
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"
  
  cluster_name    = var.eks_cluster_name
  cluster_version = "1.28"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  cluster_endpoint_public_access = true
  
  eks_managed_node_groups = {
    primary = {
      name           = "pdri-nodes"
      instance_types = [var.eks_node_type]
      
      min_size     = var.eks_node_count
      max_size     = var.eks_node_count * 3
      desired_size = var.eks_node_count
      
      labels = {
        role = "primary"
      }
    }
    
    ml = {
      name           = "pdri-ml-nodes"
      instance_types = ["p3.2xlarge"]
      
      min_size     = 0
      max_size     = var.enable_sagemaker ? 3 : 0
      desired_size = 0
      
      labels = {
        role = "ml"
      }
      
      taints = [{
        key    = "nvidia.com/gpu"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
  }
  
  tags = var.tags
}

# =============================================================================
# MSK (Kafka)
# =============================================================================
resource "aws_msk_cluster" "pdri" {
  cluster_name           = "pdri-${var.region}"
  kafka_version          = "3.5.1"
  number_of_broker_nodes = var.kafka_broker_count
  
  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = module.vpc.private_subnets
    security_groups = [aws_security_group.msk.id]
    
    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }
  
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
  
  tags = var.tags
}

resource "aws_security_group" "msk" {
  name_prefix = "pdri-msk-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 9092
    to_port     = 9098
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# =============================================================================
# RDS (PostgreSQL)
# =============================================================================
resource "aws_db_instance" "pdri" {
  identifier = "pdri-${var.region}"
  
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = var.rds_instance_type
  allocated_storage    = 100
  max_allocated_storage = 500
  
  db_name  = "pdri"
  username = "pdri_admin"
  password = random_password.rds.result
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.pdri.name
  
  multi_az               = var.region_role == "primary"
  backup_retention_period = 7
  skip_final_snapshot    = false
  final_snapshot_identifier = "pdri-${var.region}-final"
  
  tags = var.tags
}

resource "random_password" "rds" {
  length  = 32
  special = true
}

resource "aws_db_subnet_group" "pdri" {
  name       = "pdri-${var.region}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_security_group" "rds" {
  name_prefix = "pdri-rds-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

# =============================================================================
# ElastiCache (Redis)
# =============================================================================
resource "aws_elasticache_replication_group" "pdri" {
  replication_group_id       = "pdri-${var.region}"
  description                = "PDRI Redis cluster"
  
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = var.region_role == "primary" ? 2 : 1
  port                       = 6379
  
  automatic_failover_enabled = var.region_role == "primary"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  
  subnet_group_name   = aws_elasticache_subnet_group.pdri.name
  security_group_ids  = [aws_security_group.redis.id]
  
  tags = var.tags
}

resource "aws_elasticache_subnet_group" "pdri" {
  name       = "pdri-${var.region}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_security_group" "redis" {
  name_prefix = "pdri-redis-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

# =============================================================================
# Application Load Balancer
# =============================================================================
resource "aws_lb" "pdri" {
  name               = "pdri-${var.region}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
  
  tags = var.tags
}

resource "aws_security_group" "alb" {
  name_prefix = "pdri-alb-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# =============================================================================
# Outputs
# =============================================================================
output "vpc_id" {
  value = module.vpc.vpc_id
}

output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "msk_bootstrap_brokers" {
  value = aws_msk_cluster.pdri.bootstrap_brokers_tls
}

output "rds_endpoint" {
  value = aws_db_instance.pdri.endpoint
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.pdri.primary_endpoint_address
}

output "alb_dns_name" {
  value = aws_lb.pdri.dns_name
}
