"""
Multi-Region Configuration
==========================

AWS multi-region deployment configuration.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import json


class AWSRegion(Enum):
    """Supported AWS regions."""
    US_EAST_1 = "us-east-1"      # N. Virginia (Primary)
    EU_WEST_1 = "eu-west-1"      # Ireland
    AP_SOUTHEAST_1 = "ap-southeast-1"  # Singapore
    US_WEST_2 = "us-west-2"      # Oregon
    EU_CENTRAL_1 = "eu-central-1"  # Frankfurt


class RegionRole(Enum):
    """Role of a region in the deployment."""
    PRIMARY = "primary"
    SECONDARY = "secondary"
    DR = "disaster_recovery"
    READ_REPLICA = "read_replica"


@dataclass
class RegionServices:
    """Services deployed in a region."""
    eks_cluster: bool = True
    neo4j: bool = True
    kafka_msk: bool = True
    rds_postgres: bool = True
    sagemaker: bool = False
    elasticache: bool = True
    s3_bucket: bool = True


@dataclass
class RegionConfig:
    """Configuration for a single region."""
    region: AWSRegion
    role: RegionRole
    vpc_cidr: str
    availability_zones: List[str]
    services: RegionServices
    eks_node_count: int = 3
    eks_node_type: str = "m5.xlarge"
    neo4j_instance_type: str = "r5.large"
    rds_instance_type: str = "db.r5.large"
    kafka_broker_count: int = 3
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "region": self.region.value,
            "role": self.role.value,
            "vpc_cidr": self.vpc_cidr,
            "availability_zones": self.availability_zones,
            "eks_node_count": self.eks_node_count,
            "eks_node_type": self.eks_node_type,
            "enabled": self.enabled,
        }


# Default region configurations
DEFAULT_REGIONS = {
    AWSRegion.US_EAST_1: RegionConfig(
        region=AWSRegion.US_EAST_1,
        role=RegionRole.PRIMARY,
        vpc_cidr="10.0.0.0/16",
        availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"],
        services=RegionServices(sagemaker=True),
        eks_node_count=5,
    ),
    AWSRegion.EU_WEST_1: RegionConfig(
        region=AWSRegion.EU_WEST_1,
        role=RegionRole.SECONDARY,
        vpc_cidr="10.1.0.0/16",
        availability_zones=["eu-west-1a", "eu-west-1b", "eu-west-1c"],
        services=RegionServices(),
        eks_node_count=3,
    ),
    AWSRegion.AP_SOUTHEAST_1: RegionConfig(
        region=AWSRegion.AP_SOUTHEAST_1,
        role=RegionRole.SECONDARY,
        vpc_cidr="10.2.0.0/16",
        availability_zones=["ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"],
        services=RegionServices(),
        eks_node_count=3,
    ),
}


class MultiRegionManager:
    """
    Manage multi-region AWS deployments.
    
    Features:
    - Region configuration management
    - Cross-region replication setup
    - Failover orchestration
    - Health monitoring across regions
    
    Example:
        manager = MultiRegionManager()
        manager.add_region(RegionConfig(...))
        status = await manager.get_health_status()
    """
    
    def __init__(self, regions: Dict[AWSRegion, RegionConfig] = None):
        """
        Initialize multi-region manager.
        
        Args:
            regions: Initial region configurations
        """
        self.regions = regions or dict(DEFAULT_REGIONS)
        self._primary_region: Optional[AWSRegion] = None
        
        # Set primary
        for region, config in self.regions.items():
            if config.role == RegionRole.PRIMARY:
                self._primary_region = region
                break
    
    def add_region(self, config: RegionConfig) -> None:
        """Add a region to the deployment."""
        if config.role == RegionRole.PRIMARY and self._primary_region:
            raise ValueError("Only one primary region allowed")
        
        self.regions[config.region] = config
        if config.role == RegionRole.PRIMARY:
            self._primary_region = config.region
    
    def remove_region(self, region: AWSRegion) -> None:
        """Remove a region from the deployment."""
        if region == self._primary_region:
            raise ValueError("Cannot remove primary region")
        
        self.regions.pop(region, None)
    
    def get_region(self, region: AWSRegion) -> Optional[RegionConfig]:
        """Get configuration for a region."""
        return self.regions.get(region)
    
    def get_primary(self) -> Optional[RegionConfig]:
        """Get primary region configuration."""
        return self.regions.get(self._primary_region) if self._primary_region else None
    
    def list_regions(self) -> List[RegionConfig]:
        """List all configured regions."""
        return list(self.regions.values())
    
    def get_enabled_regions(self) -> List[RegionConfig]:
        """Get only enabled regions."""
        return [r for r in self.regions.values() if r.enabled]
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status across all regions."""
        status = {}
        for region, config in self.regions.items():
            if config.enabled:
                status[region.value] = await self._check_region_health(region)
        return status
    
    async def _check_region_health(self, region: AWSRegion) -> Dict[str, Any]:
        """Check health of a single region."""
        # Mock implementation
        return {
            "status": "healthy",
            "latency_ms": 45,
            "services": {
                "eks": "running",
                "neo4j": "running",
                "kafka": "running",
                "rds": "running",
            },
        }
    
    async def initiate_failover(
        self,
        from_region: AWSRegion,
        to_region: AWSRegion
    ) -> Dict[str, Any]:
        """Initiate failover from one region to another."""
        if to_region not in self.regions:
            raise ValueError(f"Target region {to_region} not configured")
        
        # Failover steps
        steps = [
            "Verify target region health",
            "Update Route53 weights",
            "Switch database primary",
            "Redirect traffic",
            "Verify services",
        ]
        
        return {
            "failover_id": "fo-000001",
            "from_region": from_region.value,
            "to_region": to_region.value,
            "status": "initiated",
            "steps": steps,
            "estimated_time_seconds": 120,
        }
    
    def generate_terraform_vars(self) -> str:
        """Generate Terraform variables for all regions."""
        regions_config = {}
        for region, config in self.regions.items():
            if config.enabled:
                regions_config[region.value] = config.to_dict()
        
        return json.dumps({"regions": regions_config}, indent=2)
    
    def get_replication_topology(self) -> Dict[str, List[str]]:
        """Get data replication topology."""
        topology = {}
        if self._primary_region:
            primary = self._primary_region.value
            replicas = [
                r.value for r, c in self.regions.items()
                if r != self._primary_region and c.enabled
            ]
            topology[primary] = replicas
        return topology
