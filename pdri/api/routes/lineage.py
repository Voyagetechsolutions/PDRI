"""
PDRI AI Data Lineage Routes
============================

API endpoints for tracking data flow through AI systems.

These endpoints provide:
    - Forward lineage: Data → Dataset → Model → Endpoint → Output
    - Backward lineage: Model → Dataset → Data sources
    - Sensitive data in AI detection
    - External AI exposure analysis
    - AI-specific blast radius calculation

Author: PDRI Team
Version: 1.0.0
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from pdri.api.dependencies import ServiceContainer


router = APIRouter(prefix="/api/v1/lineage", tags=["AI Data Lineage"])


# =============================================================================
# Response Models
# =============================================================================

class DataSource(BaseModel):
    """A data source in lineage."""
    id: str
    name: Optional[str] = None
    classification: Optional[str] = None
    sensitivity: Optional[float] = None


class AILineagePath(BaseModel):
    """A path in AI data lineage."""
    source_id: str
    source_name: Optional[str] = None
    source_sensitivity: Optional[float] = None
    dataset_id: Optional[str] = None
    contains_pii: Optional[bool] = None
    model_id: Optional[str] = None
    model_name: Optional[str] = None
    is_external: Optional[bool] = None
    endpoint_id: Optional[str] = None
    is_public_endpoint: Optional[bool] = None
    output_id: Optional[str] = None
    output_shared: Optional[bool] = None
    external_id: Optional[str] = None
    external_name: Optional[str] = None


class ModelTrainingSources(BaseModel):
    """Training sources for an AI model."""
    model_id: str
    model_name: str
    dataset_id: Optional[str] = None
    dataset_name: Optional[str] = None
    contains_pii: Optional[bool] = None
    contains_secrets: Optional[bool] = None
    data_categories: List[str] = []
    data_sources: List[DataSource] = []


class SensitiveAIData(BaseModel):
    """Sensitive data used in AI systems."""
    source_id: str
    source_name: str
    classification: Optional[str] = None
    sensitivity: float
    dataset_id: Optional[str] = None
    contains_pii: Optional[bool] = None
    contains_secrets: Optional[bool] = None
    model_id: str
    model_name: str
    is_external: bool
    can_memorize: Optional[bool] = None


class ExternalAIExposure(BaseModel):
    """Data exposed to external AI systems."""
    source_id: str
    source_name: str
    sensitivity: float
    ai_id: str
    ai_name: str
    ai_type: str
    vendor: Optional[str] = None


class AIBlastRadius(BaseModel):
    """Blast radius for AI impact."""
    source_id: str
    source_name: str
    affected_datasets: int
    affected_models: int
    external_models: int
    affected_endpoints: int
    public_endpoints: int
    affected_outputs: int
    model_ids: List[str] = []
    endpoint_ids: List[str] = []


class AIDataInventoryItem(BaseModel):
    """Item in AI data inventory."""
    dataset_id: str
    dataset_name: str
    classification: Optional[str] = None
    contains_pii: Optional[bool] = None
    contains_secrets: Optional[bool] = None
    categories: List[str] = []
    source_ids: List[str] = []
    model_ids: List[str] = []
    model_count: int


class ModelSensitivity(BaseModel):
    """Model with data sensitivity info."""
    model_id: str
    model_name: str
    is_external: bool
    vendor: Optional[str] = None
    data_sensitivity: Optional[float] = None
    highest_classification: str


class LineageSummary(BaseModel):
    """Summary of AI lineage metrics."""
    total_models: int
    external_models: int
    models_with_pii: int
    models_with_sensitive_data: int
    public_endpoints: int
    datasets_with_pii: int
    external_exposures: int


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/forward/{data_store_id}",
    response_model=List[AILineagePath],
    summary="Trace Data Forward to AI",
    description="Trace how data from a store flows into AI systems.",
)
async def trace_forward(
    data_store_id: str,
    limit: int = Query(50, ge=1, le=200),
) -> List[AILineagePath]:
    """
    Trace data forward from source to AI systems.

    Shows: DataStore → Dataset → Model path
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    paths = await container.graph_engine.trace_data_to_ai(data_store_id, limit)

    return [AILineagePath(**p) for p in paths]


@router.get(
    "/full",
    response_model=List[AILineagePath],
    summary="Trace Full AI Lineage",
    description="Get complete end-to-end AI data lineage.",
)
async def trace_full_lineage(
    min_sensitivity: float = Query(0.5, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
) -> List[AILineagePath]:
    """
    Trace complete AI lineage end-to-end.

    Shows: Source → Dataset → Model → Endpoint → Output → External
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    paths = await container.graph_engine.trace_full_ai_lineage(min_sensitivity, limit)

    return [AILineagePath(**p) for p in paths]


@router.get(
    "/backward/{model_id}",
    response_model=ModelTrainingSources,
    summary="Trace Model Training Sources",
    description="Find all data sources that contributed to a model's training.",
)
async def trace_backward(
    model_id: str,
) -> ModelTrainingSources:
    """
    Trace backward from model to training data sources.

    Shows: Model → Dataset → DataStore sources
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    result = await container.graph_engine.trace_model_training_sources(model_id)

    if not result:
        raise HTTPException(status_code=404, detail=f"Model {model_id} not found")

    # Convert data_sources from list of dicts
    data_sources = [
        DataSource(**ds) for ds in result.get("data_sources", [])
        if ds.get("id")  # Filter out nulls
    ]

    return ModelTrainingSources(
        model_id=result["model_id"],
        model_name=result["model_name"],
        dataset_id=result.get("dataset_id"),
        dataset_name=result.get("dataset_name"),
        contains_pii=result.get("contains_pii"),
        contains_secrets=result.get("contains_secrets"),
        data_categories=result.get("data_categories", []),
        data_sources=data_sources,
    )


@router.get(
    "/sensitive-data",
    response_model=List[SensitiveAIData],
    summary="Find Sensitive Data in AI",
    description="Find sensitive data being used by AI systems.",
)
async def get_sensitive_ai_data(
    min_sensitivity: float = Query(0.5, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
) -> List[SensitiveAIData]:
    """
    Find sensitive data flowing into AI systems.

    Identifies data stores with high sensitivity or PII
    that are used for AI training.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    data = await container.graph_engine.find_sensitive_data_in_ai(
        min_sensitivity, limit
    )

    return [SensitiveAIData(**d) for d in data]


@router.get(
    "/external-exposure",
    response_model=List[ExternalAIExposure],
    summary="Find External AI Exposure",
    description="Find internal data exposed to external AI services.",
)
async def get_external_exposure(
    limit: int = Query(50, ge=1, le=200),
) -> List[ExternalAIExposure]:
    """
    Find data exposed to external AI systems.

    Identifies internal data flowing to third-party AI
    (OpenAI, Anthropic, etc.).
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    exposures = await container.graph_engine.find_external_ai_exposure(limit)

    return [ExternalAIExposure(**e) for e in exposures]


@router.get(
    "/blast-radius/{data_store_id}",
    response_model=AIBlastRadius,
    summary="Calculate AI Blast Radius",
    description="Calculate AI-specific impact if data source is compromised.",
)
async def get_ai_blast_radius(
    data_store_id: str,
) -> AIBlastRadius:
    """
    Calculate AI-specific blast radius.

    If this data source is compromised, which AI systems
    could be affected?
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    result = await container.graph_engine.calculate_data_ai_blast_radius(data_store_id)

    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Data store {data_store_id} not found"
        )

    return AIBlastRadius(**result)


@router.get(
    "/inventory",
    response_model=List[AIDataInventoryItem],
    summary="Get AI Data Inventory",
    description="Get inventory of all data used in AI systems.",
)
async def get_ai_inventory() -> List[AIDataInventoryItem]:
    """
    Get complete AI data inventory.

    Returns all training datasets, their sources,
    and which models use them.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    inventory = await container.graph_engine.get_ai_data_inventory()

    return [AIDataInventoryItem(**item) for item in inventory]


@router.get(
    "/models-by-sensitivity",
    response_model=List[ModelSensitivity],
    summary="Get Models by Data Sensitivity",
    description="Get AI models grouped by training data sensitivity.",
)
async def get_models_by_sensitivity(
    limit: int = Query(50, ge=1, le=200),
) -> List[ModelSensitivity]:
    """
    Get models ordered by training data sensitivity.

    Identifies models trained on sensitive data that
    may require additional controls.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    models = await container.graph_engine.get_models_by_data_sensitivity(limit)

    return [ModelSensitivity(**m) for m in models]


@router.get(
    "/summary",
    response_model=LineageSummary,
    summary="Get Lineage Summary",
    description="Get summary metrics for AI data lineage.",
)
async def get_lineage_summary() -> LineageSummary:
    """
    Get summary of AI lineage metrics.

    Dashboard-level view of AI data governance.
    """
    container = ServiceContainer.get_instance()

    if not container.graph_available or not container.graph_engine:
        return LineageSummary(
            total_models=0,
            external_models=0,
            models_with_pii=0,
            models_with_sensitive_data=0,
            public_endpoints=0,
            datasets_with_pii=0,
            external_exposures=0,
        )

    # Get data for summary
    models = await container.graph_engine.get_models_by_data_sensitivity(limit=1000)
    sensitive = await container.graph_engine.find_sensitive_data_in_ai(0.5, 1000)
    external = await container.graph_engine.find_external_ai_exposure(1000)
    inventory = await container.graph_engine.get_ai_data_inventory()

    # Calculate metrics
    total_models = len(models)
    external_models = sum(1 for m in models if m.get("is_external"))
    models_with_sensitive = sum(
        1 for m in models
        if (m.get("data_sensitivity") or 0) >= 0.5
        or m.get("highest_classification") in ["confidential", "restricted"]
    )

    # Get unique models with PII from sensitive data
    pii_model_ids = {s["model_id"] for s in sensitive if s.get("contains_pii")}
    models_with_pii = len(pii_model_ids)

    # Datasets with PII
    datasets_with_pii = sum(1 for i in inventory if i.get("contains_pii"))

    return LineageSummary(
        total_models=total_models,
        external_models=external_models,
        models_with_pii=models_with_pii,
        models_with_sensitive_data=models_with_sensitive,
        public_endpoints=0,  # Would need endpoint query
        datasets_with_pii=datasets_with_pii,
        external_exposures=len(external),
    )
