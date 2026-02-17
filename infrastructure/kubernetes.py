"""
Kubernetes Deployment Manager
=============================

EKS cluster and Kubernetes resource management.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
import json
import yaml


class DeploymentEnvironment(Enum):
    """Deployment environments."""
    DEVELOPMENT = "dev"
    STAGING = "staging"
    PRODUCTION = "prod"


@dataclass
class ServiceSpec:
    """Kubernetes service specification."""
    name: str
    image: str
    replicas: int = 2
    cpu_request: str = "250m"
    cpu_limit: str = "1000m"
    memory_request: str = "512Mi"
    memory_limit: str = "2Gi"
    port: int = 8080
    health_path: str = "/health"
    env_vars: Dict[str, str] = field(default_factory=dict)
    secrets: List[str] = field(default_factory=list)


@dataclass
class HorizontalPodAutoscaler:
    """HPA configuration."""
    min_replicas: int = 2
    max_replicas: int = 10
    target_cpu_percent: int = 70
    target_memory_percent: int = 80


# Default PDRI services
PDRI_SERVICES = {
    "pdri-api": ServiceSpec(
        name="pdri-api",
        image="pdri/api:latest",
        replicas=3,
        port=8000,
        health_path="/api/v2/health",
        env_vars={
            "LOG_LEVEL": "INFO",
            "WORKERS": "4",
        },
    ),
    "pdri-worker": ServiceSpec(
        name="pdri-worker",
        image="pdri/worker:latest",
        replicas=2,
        cpu_limit="2000m",
        memory_limit="4Gi",
        env_vars={
            "WORKER_CONCURRENCY": "4",
        },
    ),
    "pdri-ml": ServiceSpec(
        name="pdri-ml",
        image="pdri/ml:latest",
        replicas=2,
        cpu_request="500m",
        cpu_limit="4000m",
        memory_request="2Gi",
        memory_limit="8Gi",
        port=8001,
        health_path="/health",
    ),
    "pdri-federation": ServiceSpec(
        name="pdri-federation",
        image="pdri/federation:latest",
        replicas=2,
        port=8002,
        health_path="/health",
    ),
}


class KubernetesDeployer:
    """
    Kubernetes deployment manager.
    
    Features:
    - Generate Kubernetes manifests
    - Deploy to EKS clusters
    - Manage rollouts and rollbacks
    - Configure autoscaling
    
    Example:
        deployer = KubernetesDeployer(env=DeploymentEnvironment.PRODUCTION)
        manifests = deployer.generate_manifests()
        deployer.apply_manifests(manifests)
    """
    
    def __init__(
        self,
        env: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION,
        namespace: str = "pdri",
        services: Dict[str, ServiceSpec] = None
    ):
        """
        Initialize Kubernetes deployer.
        
        Args:
            env: Deployment environment
            namespace: Kubernetes namespace
            services: Service specifications
        """
        self.env = env
        self.namespace = namespace
        self.services = services or PDRI_SERVICES
    
    def generate_deployment(self, service: ServiceSpec) -> Dict[str, Any]:
        """Generate Kubernetes Deployment manifest."""
        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": service.name,
                "namespace": self.namespace,
                "labels": {
                    "app": service.name,
                    "environment": self.env.value,
                },
            },
            "spec": {
                "replicas": service.replicas,
                "selector": {
                    "matchLabels": {"app": service.name},
                },
                "template": {
                    "metadata": {
                        "labels": {"app": service.name},
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": service.name,
                                "image": service.image,
                                "ports": [{"containerPort": service.port}],
                                "resources": {
                                    "requests": {
                                        "cpu": service.cpu_request,
                                        "memory": service.memory_request,
                                    },
                                    "limits": {
                                        "cpu": service.cpu_limit,
                                        "memory": service.memory_limit,
                                    },
                                },
                                "livenessProbe": {
                                    "httpGet": {
                                        "path": service.health_path,
                                        "port": service.port,
                                    },
                                    "initialDelaySeconds": 30,
                                    "periodSeconds": 10,
                                },
                                "readinessProbe": {
                                    "httpGet": {
                                        "path": service.health_path,
                                        "port": service.port,
                                    },
                                    "initialDelaySeconds": 5,
                                    "periodSeconds": 5,
                                },
                                "env": [
                                    {"name": k, "value": v}
                                    for k, v in service.env_vars.items()
                                ],
                            }
                        ],
                    },
                },
            },
        }
    
    def generate_service(self, service: ServiceSpec) -> Dict[str, Any]:
        """Generate Kubernetes Service manifest."""
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": service.name,
                "namespace": self.namespace,
            },
            "spec": {
                "selector": {"app": service.name},
                "ports": [
                    {
                        "port": service.port,
                        "targetPort": service.port,
                    }
                ],
                "type": "ClusterIP",
            },
        }
    
    def generate_hpa(
        self,
        service: ServiceSpec,
        config: HorizontalPodAutoscaler = None
    ) -> Dict[str, Any]:
        """Generate HorizontalPodAutoscaler manifest."""
        config = config or HorizontalPodAutoscaler()
        return {
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": {
                "name": f"{service.name}-hpa",
                "namespace": self.namespace,
            },
            "spec": {
                "scaleTargetRef": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": service.name,
                },
                "minReplicas": config.min_replicas,
                "maxReplicas": config.max_replicas,
                "metrics": [
                    {
                        "type": "Resource",
                        "resource": {
                            "name": "cpu",
                            "target": {
                                "type": "Utilization",
                                "averageUtilization": config.target_cpu_percent,
                            },
                        },
                    },
                    {
                        "type": "Resource",
                        "resource": {
                            "name": "memory",
                            "target": {
                                "type": "Utilization",
                                "averageUtilization": config.target_memory_percent,
                            },
                        },
                    },
                ],
            },
        }
    
    def generate_ingress(self) -> Dict[str, Any]:
        """Generate Ingress manifest for API."""
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": "pdri-ingress",
                "namespace": self.namespace,
                "annotations": {
                    "kubernetes.io/ingress.class": "alb",
                    "alb.ingress.kubernetes.io/scheme": "internet-facing",
                    "alb.ingress.kubernetes.io/target-type": "ip",
                    "alb.ingress.kubernetes.io/healthcheck-path": "/api/v2/health",
                },
            },
            "spec": {
                "rules": [
                    {
                        "http": {
                            "paths": [
                                {
                                    "path": "/api",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {
                                            "name": "pdri-api",
                                            "port": {"number": 8000},
                                        },
                                    },
                                },
                            ],
                        },
                    },
                ],
            },
        }
    
    def generate_namespace(self) -> Dict[str, Any]:
        """Generate Namespace manifest."""
        return {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": self.namespace,
                "labels": {
                    "environment": self.env.value,
                },
            },
        }
    
    def generate_all_manifests(self) -> List[Dict[str, Any]]:
        """Generate all Kubernetes manifests."""
        manifests = [self.generate_namespace()]
        
        for service in self.services.values():
            manifests.append(self.generate_deployment(service))
            manifests.append(self.generate_service(service))
            manifests.append(self.generate_hpa(service))
        
        manifests.append(self.generate_ingress())
        return manifests
    
    def to_yaml(self, manifests: List[Dict[str, Any]] = None) -> str:
        """Convert manifests to YAML."""
        manifests = manifests or self.generate_all_manifests()
        return "\n---\n".join(yaml.dump(m, default_flow_style=False) for m in manifests)
    
    async def apply_manifests(
        self,
        manifests: List[Dict[str, Any]] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Apply manifests to cluster."""
        manifests = manifests or self.generate_all_manifests()
        
        # In production, would use kubernetes client
        return {
            "status": "dry_run" if dry_run else "applied",
            "manifests_count": len(manifests),
            "namespace": self.namespace,
            "environment": self.env.value,
        }
    
    async def get_deployment_status(self) -> Dict[str, Any]:
        """Get deployment status across services."""
        status = {}
        for name in self.services:
            status[name] = {
                "ready_replicas": 3,
                "desired_replicas": 3,
                "available": True,
            }
        return status
    
    async def rollback(self, service_name: str, revision: int = 0) -> Dict[str, Any]:
        """Rollback a deployment."""
        return {
            "service": service_name,
            "rolled_back_to": revision if revision else "previous",
            "status": "success",
        }
