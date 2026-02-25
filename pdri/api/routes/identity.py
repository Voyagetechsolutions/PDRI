"""
PDRI Identity Analytics Routes
==============================

API endpoints for identity-aware risk analysis and blast radius calculation.

These endpoints provide:
    - Blast radius calculation per identity
    - Access path analysis (Identity → Role → Permission → Resource)
    - Privileged identity discovery
    - Over-permissioned identity detection
    - Group blast radius analysis

Author: PDRI Team
Version: 1.0.0
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from pdri.api.dependencies import ServiceContainer


router = APIRouter(prefix="/api/v1/identity", tags=["Identity Analytics"])


# =============================================================================
# Response Models
# =============================================================================

class BlastRadiusBreakdown(BaseModel):
    """Breakdown of blast radius by resource type."""
    data_stores: int = Field(description="Number of data stores affected")
    services: int = Field(description="Number of services affected")
    ai_tools: int = Field(description="Number of AI tools affected")


class RiskMetrics(BaseModel):
    """Risk metrics for blast radius."""
    critical_resources: int = Field(description="Resources with sensitivity >= 0.8")
    sensitive_resources: int = Field(description="Resources with sensitivity >= 0.5")
    avg_sensitivity: Optional[float] = Field(description="Average sensitivity of accessible resources")
    max_sensitivity: Optional[float] = Field(description="Maximum sensitivity of accessible resources")


class BlastRadiusResponse(BaseModel):
    """Response for blast radius calculation."""
    identity_id: str
    identity_name: Optional[str] = None
    privilege_level: Optional[str] = None
    found: bool
    blast_radius: int = Field(description="Total number of resources affected")
    breakdown: Optional[BlastRadiusBreakdown] = None
    risk_metrics: Optional[RiskMetrics] = None
    resource_ids: Optional[List[str]] = None
    message: Optional[str] = None


class AccessibleResource(BaseModel):
    """A resource accessible by an identity."""
    id: str
    name: str
    type: str
    sensitivity: Optional[float] = None


class ExternalExposure(BaseModel):
    """An external exposure point."""
    id: str
    name: str
    type: str


class DownstreamBlastRadiusResponse(BaseModel):
    """Response for blast radius with downstream exposure."""
    identity_id: str
    identity_name: Optional[str] = None
    found: bool
    direct_blast_radius: int
    downstream_exposure_count: int
    total_blast_radius: int
    accessible_resources: List[AccessibleResource]
    external_exposures: List[ExternalExposure]


class AccessPath(BaseModel):
    """An access path from identity to resource."""
    identity_id: str
    identity_name: str
    role_id: Optional[str] = None
    role_name: Optional[str] = None
    is_privileged: Optional[bool] = None
    permission_id: Optional[str] = None
    action: Optional[str] = None
    resource_id: str
    resource_name: str
    resource_type: str
    sensitivity: Optional[float] = None


class PrivilegedIdentity(BaseModel):
    """A privileged identity."""
    identity_id: str
    identity_name: str
    identity_type: Optional[str] = None
    has_mfa: Optional[bool] = None
    privileged_roles: List[str]
    privileged_role_count: int


class OverPermissionedIdentity(BaseModel):
    """An identity with more permissions than used."""
    identity_id: str
    identity_name: str
    permitted_resources: int
    actually_accessed: int
    total_accesses: int
    utilization_ratio: float
    unused_permissions: int


class GroupBlastRadius(BaseModel):
    """Blast radius for a group."""
    group_id: str
    group_name: str
    member_count: int
    blast_radius: int
    high_sensitivity_resources: List[str]


class UnauthorizedAccess(BaseModel):
    """An unauthorized access path."""
    identity_id: str
    identity_name: str
    resource_id: str
    resource_name: str
    resource_type: str
    access_count: Optional[int] = None


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/blast-radius/{identity_id}",
    response_model=BlastRadiusResponse,
    summary="Calculate Identity Blast Radius",
    description="Calculate how many resources would be exposed if this identity is compromised.",
)
async def get_blast_radius(
    identity_id: str,
) -> BlastRadiusResponse:
    """
    Calculate blast radius for a specific identity.

    Returns:
        - Total number of resources the identity can access
        - Breakdown by resource type (data stores, services, AI tools)
        - Risk metrics (critical/sensitive resource counts)
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(
            status_code=503,
            detail="Graph database unavailable for blast radius calculation"
        )

    result = await container.graph_engine.calculate_blast_radius(
        identity_id=identity_id,
        include_downstream=False
    )

    if not result.get("found", False):
        raise HTTPException(status_code=404, detail=f"Identity {identity_id} not found")

    return BlastRadiusResponse(
        identity_id=result["identity_id"],
        identity_name=result.get("identity_name"),
        privilege_level=result.get("privilege_level"),
        found=True,
        blast_radius=result["blast_radius"],
        breakdown=BlastRadiusBreakdown(**result["breakdown"]) if result.get("breakdown") else None,
        risk_metrics=RiskMetrics(**result["risk_metrics"]) if result.get("risk_metrics") else None,
        resource_ids=result.get("resource_ids"),
    )


@router.get(
    "/blast-radius/{identity_id}/downstream",
    response_model=DownstreamBlastRadiusResponse,
    summary="Calculate Blast Radius with Downstream Exposure",
    description="Calculate blast radius including resources that accessible resources expose to.",
)
async def get_blast_radius_downstream(
    identity_id: str,
) -> DownstreamBlastRadiusResponse:
    """
    Calculate blast radius including downstream exposure.

    This goes beyond direct access and calculates what external
    entities (AI tools, external services) would gain access
    to the data through the compromised identity.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(
            status_code=503,
            detail="Graph database unavailable"
        )

    result = await container.graph_engine.calculate_blast_radius(
        identity_id=identity_id,
        include_downstream=True
    )

    if not result.get("found", False):
        raise HTTPException(status_code=404, detail=f"Identity {identity_id} not found")

    return DownstreamBlastRadiusResponse(
        identity_id=result["identity_id"],
        identity_name=result.get("identity_name"),
        found=True,
        direct_blast_radius=result["direct_blast_radius"],
        downstream_exposure_count=result["downstream_exposure_count"],
        total_blast_radius=result["total_blast_radius"],
        accessible_resources=[
            AccessibleResource(**r) for r in result.get("accessible_resources", [])
        ],
        external_exposures=[
            ExternalExposure(**e) for e in result.get("external_exposures", [])
        ],
    )


@router.get(
    "/access-paths/{identity_id}",
    response_model=List[AccessPath],
    summary="Get Identity Access Paths",
    description="Find all access paths from an identity to resources via roles and permissions.",
)
async def get_access_paths(
    identity_id: str,
    limit: int = Query(50, ge=1, le=200),
) -> List[AccessPath]:
    """
    Get all access paths for an identity.

    Returns Identity → Role → Permission → Resource paths,
    useful for understanding how an identity gains access.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    paths = await container.graph_engine.find_identity_access_paths(
        identity_id=identity_id,
        limit=limit
    )

    return [AccessPath(**p) for p in paths]


@router.get(
    "/privileged",
    response_model=List[PrivilegedIdentity],
    summary="Get Privileged Identities",
    description="Get all identities with privileged/admin roles.",
)
async def get_privileged_identities(
    limit: int = Query(50, ge=1, le=200),
) -> List[PrivilegedIdentity]:
    """
    Get all privileged identities.

    Returns identities with elevated access for security audits.
    Includes MFA status and role details.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    identities = await container.graph_engine.get_privileged_identities(limit=limit)

    return [PrivilegedIdentity(**i) for i in identities]


@router.get(
    "/over-permissioned",
    response_model=List[OverPermissionedIdentity],
    summary="Get Over-Permissioned Identities",
    description="Find identities with more permissions than they actually use.",
)
async def get_over_permissioned(
    limit: int = Query(50, ge=1, le=200),
) -> List[OverPermissionedIdentity]:
    """
    Find over-permissioned identities.

    Identifies potential security risks where identities have
    access they don't use (violates least privilege principle).
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    identities = await container.graph_engine.get_over_permissioned_identities(limit=limit)

    return [OverPermissionedIdentity(**i) for i in identities]


@router.get(
    "/groups/blast-radius",
    response_model=List[GroupBlastRadius],
    summary="Get Group Blast Radius",
    description="Calculate blast radius for all groups based on combined member access.",
)
async def get_group_blast_radius(
    limit: int = Query(20, ge=1, le=100),
) -> List[GroupBlastRadius]:
    """
    Get blast radius for all groups.

    Calculates aggregate exposure if an entire group is compromised.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    groups = await container.graph_engine.get_group_blast_radius(limit=limit)

    return [GroupBlastRadius(**g) for g in groups]


@router.get(
    "/unauthorized-access",
    response_model=List[UnauthorizedAccess],
    summary="Find Unauthorized Access Paths",
    description="Find direct accesses that bypass role-based permissions.",
)
async def get_unauthorized_access(
    limit: int = Query(50, ge=1, le=200),
) -> List[UnauthorizedAccess]:
    """
    Find unauthorized access paths.

    Identifies compliance issues where identities access
    resources without proper role/permission authorization.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    accesses = await container.graph_engine.find_unauthorized_access_paths(limit=limit)

    return [UnauthorizedAccess(**a) for a in accesses]


@router.get(
    "/summary",
    summary="Identity Risk Summary",
    description="Get overall identity-related risk summary.",
)
async def get_identity_summary() -> Dict[str, Any]:
    """
    Get identity risk summary.

    Returns aggregate metrics about identity-related risks:
    - Total privileged identities
    - Over-permissioned count
    - Groups with high blast radius
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        return {
            "available": False,
            "message": "Graph database unavailable"
        }

    # Get summary data in parallel-ish
    privileged = await container.graph_engine.get_privileged_identities(limit=100)
    over_perm = await container.graph_engine.get_over_permissioned_identities(limit=100)
    groups = await container.graph_engine.get_group_blast_radius(limit=100)

    # Calculate aggregates
    total_privileged = len(privileged)
    privileged_without_mfa = sum(1 for p in privileged if not p.get("has_mfa", False))
    total_over_permissioned = len(over_perm)
    avg_utilization = (
        sum(o.get("utilization_ratio", 0) for o in over_perm) / len(over_perm)
        if over_perm else 0
    )
    high_blast_groups = sum(1 for g in groups if g.get("blast_radius", 0) > 50)

    return {
        "available": True,
        "identity_metrics": {
            "privileged_identities": total_privileged,
            "privileged_without_mfa": privileged_without_mfa,
            "over_permissioned_identities": total_over_permissioned,
            "avg_permission_utilization": round(avg_utilization, 2),
        },
        "group_metrics": {
            "total_groups": len(groups),
            "high_blast_radius_groups": high_blast_groups,
            "max_group_blast_radius": max((g.get("blast_radius", 0) for g in groups), default=0),
        },
        "recommendations": _generate_recommendations(
            total_privileged,
            privileged_without_mfa,
            total_over_permissioned,
            high_blast_groups
        ),
    }


def _generate_recommendations(
    privileged: int,
    without_mfa: int,
    over_perm: int,
    high_blast_groups: int
) -> List[Dict[str, str]]:
    """Generate actionable recommendations based on metrics."""
    recommendations = []

    if without_mfa > 0:
        recommendations.append({
            "severity": "critical",
            "category": "mfa",
            "message": f"{without_mfa} privileged identities lack MFA - enable MFA immediately",
        })

    if over_perm > 10:
        recommendations.append({
            "severity": "high",
            "category": "least_privilege",
            "message": f"{over_perm} identities have unused permissions - review and revoke",
        })

    if high_blast_groups > 3:
        recommendations.append({
            "severity": "medium",
            "category": "group_access",
            "message": f"{high_blast_groups} groups have high blast radius - consider splitting",
        })

    if privileged > 20:
        recommendations.append({
            "severity": "medium",
            "category": "privileged_access",
            "message": f"{privileged} privileged identities - audit necessity of elevated access",
        })

    return recommendations
