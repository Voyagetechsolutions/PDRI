"""
Evidence Collector
==================

Automated evidence collection for compliance audits.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import json


class EvidenceType(Enum):
    """Types of compliance evidence."""
    SCREENSHOT = "screenshot"
    LOG_EXTRACT = "log_extract"
    CONFIG_SNAPSHOT = "config_snapshot"
    POLICY_DOCUMENT = "policy_document"
    TEST_RESULT = "test_result"
    ATTESTATION = "attestation"
    GRAPH_QUERY = "graph_query"
    RISK_REPORT = "risk_report"


@dataclass
class Evidence:
    """A piece of compliance evidence."""
    evidence_id: str
    evidence_type: EvidenceType
    control_id: str
    framework: str
    title: str
    description: str
    collected_at: datetime
    collected_by: str
    content: Any  # The actual evidence content
    content_hash: str  # For integrity verification
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "control_id": self.control_id,
            "framework": self.framework,
            "title": self.title,
            "description": self.description,
            "collected_at": self.collected_at.isoformat(),
            "collected_by": self.collected_by,
            "content_hash": self.content_hash,
            "metadata": self.metadata,
        }


class EvidenceCollector:
    """
    Automated evidence collection for compliance.
    
    Collects evidence from:
    - PDRI graph database
    - Audit trail
    - Configuration snapshots
    - Test results
    
    Example:
        collector = EvidenceCollector(graph_engine, audit_trail)
        evidence = await collector.collect_for_control("AC-2", "fedramp")
    """
    
    def __init__(
        self,
        graph_engine: Any = None,
        audit_trail: Any = None,
        storage_path: str = "./evidence"
    ):
        """
        Initialize evidence collector.
        
        Args:
            graph_engine: Graph database for data evidence
            audit_trail: Audit trail for log evidence
            storage_path: Path for storing evidence files
        """
        self.graph_engine = graph_engine
        self.audit_trail = audit_trail
        self.storage_path = storage_path
        
        self._evidence: List[Evidence] = []
        self._evidence_counter = 0
    
    async def collect_for_control(
        self,
        control_id: str,
        framework: str
    ) -> List[Evidence]:
        """
        Collect all evidence for a control.
        
        Args:
            control_id: Control identifier
            framework: Compliance framework
        
        Returns:
            List of collected evidence
        """
        evidence_list = []
        
        # Collect from different sources
        graph_evidence = await self._collect_graph_evidence(control_id, framework)
        if graph_evidence:
            evidence_list.append(graph_evidence)
        
        log_evidence = await self._collect_log_evidence(control_id, framework)
        if log_evidence:
            evidence_list.append(log_evidence)
        
        config_evidence = await self._collect_config_evidence(control_id, framework)
        if config_evidence:
            evidence_list.append(config_evidence)
        
        return evidence_list
    
    async def _collect_graph_evidence(
        self,
        control_id: str,
        framework: str
    ) -> Optional[Evidence]:
        """Collect evidence from PDRI graph."""
        if not self.graph_engine:
            return None
        
        self._evidence_counter += 1
        evidence_id = f"evd-{self._evidence_counter:06d}"
        
        # Run relevant query based on control
        query_result = await self._run_control_query(control_id)
        
        content = json.dumps(query_result, default=str)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.GRAPH_QUERY,
            control_id=control_id,
            framework=framework,
            title=f"Graph Query for {control_id}",
            description=f"PDRI graph data supporting {control_id} compliance",
            collected_at=datetime.utcnow(),
            collected_by="pdri-evidence-collector",
            content=query_result,
            content_hash=content_hash,
            metadata={"query_type": "control_evidence"},
        )
        
        self._evidence.append(evidence)
        return evidence
    
    async def _collect_log_evidence(
        self,
        control_id: str,
        framework: str
    ) -> Optional[Evidence]:
        """Collect evidence from audit logs."""
        if not self.audit_trail:
            return None
        
        self._evidence_counter += 1
        evidence_id = f"evd-{self._evidence_counter:06d}"
        
        # Get relevant audit events
        from datetime import timedelta
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)
        
        if hasattr(self.audit_trail, 'query'):
            events = self.audit_trail.query(start_time=start_time, end_time=end_time, limit=100)
            event_data = [e.to_dict() for e in events]
        else:
            event_data = []
        
        content = json.dumps(event_data, default=str)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.LOG_EXTRACT,
            control_id=control_id,
            framework=framework,
            title=f"Audit Log Extract for {control_id}",
            description=f"Audit events demonstrating {control_id} compliance",
            collected_at=datetime.utcnow(),
            collected_by="pdri-evidence-collector",
            content=event_data,
            content_hash=content_hash,
            metadata={"event_count": len(event_data), "period_days": 30},
        )
        
        self._evidence.append(evidence)
        return evidence
    
    async def _collect_config_evidence(
        self,
        control_id: str,
        framework: str
    ) -> Optional[Evidence]:
        """Collect configuration snapshot evidence."""
        self._evidence_counter += 1
        evidence_id = f"evd-{self._evidence_counter:06d}"
        
        # Mock configuration snapshot
        config_snapshot = {
            "pdri_version": "2.0.0",
            "security_settings": {
                "mfa_enabled": True,
                "encryption_at_rest": True,
                "audit_logging": True,
            },
            "collected_at": datetime.utcnow().isoformat(),
        }
        
        content = json.dumps(config_snapshot, default=str)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.CONFIG_SNAPSHOT,
            control_id=control_id,
            framework=framework,
            title=f"Configuration Snapshot for {control_id}",
            description="Current PDRI configuration settings",
            collected_at=datetime.utcnow(),
            collected_by="pdri-evidence-collector",
            content=config_snapshot,
            content_hash=content_hash,
            metadata={},
        )
        
        self._evidence.append(evidence)
        return evidence
    
    async def _run_control_query(self, control_id: str) -> Dict[str, Any]:
        """Run graph query for control evidence."""
        # Mock query results based on control
        return {
            "control_id": control_id,
            "data_points_analyzed": 150,
            "compliance_indicators": ["access_controls", "monitoring", "encryption"],
            "query_timestamp": datetime.utcnow().isoformat(),
        }
    
    async def collect_for_assessment(
        self,
        assessment_id: str,
        framework: str,
        control_ids: List[str]
    ) -> Dict[str, List[Evidence]]:
        """Collect evidence for full assessment."""
        evidence_by_control = {}
        
        for control_id in control_ids:
            evidence_list = await self.collect_for_control(control_id, framework)
            evidence_by_control[control_id] = evidence_list
        
        return evidence_by_control
    
    def add_manual_evidence(
        self,
        control_id: str,
        framework: str,
        evidence_type: EvidenceType,
        title: str,
        description: str,
        content: Any,
        collected_by: str
    ) -> Evidence:
        """Add manually collected evidence."""
        self._evidence_counter += 1
        evidence_id = f"evd-{self._evidence_counter:06d}"
        
        content_str = json.dumps(content, default=str) if not isinstance(content, str) else content
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()
        
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            control_id=control_id,
            framework=framework,
            title=title,
            description=description,
            collected_at=datetime.utcnow(),
            collected_by=collected_by,
            content=content,
            content_hash=content_hash,
            metadata={"manual": True},
        )
        
        self._evidence.append(evidence)
        return evidence
    
    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        return next((e for e in self._evidence if e.evidence_id == evidence_id), None)
    
    def list_evidence(
        self,
        control_id: Optional[str] = None,
        framework: Optional[str] = None
    ) -> List[Evidence]:
        """List evidence with optional filtering."""
        results = self._evidence
        if control_id:
            results = [e for e in results if e.control_id == control_id]
        if framework:
            results = [e for e in results if e.framework == framework]
        return results
    
    def verify_evidence(self, evidence_id: str) -> bool:
        """Verify evidence integrity."""
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            return False
        
        content_str = json.dumps(evidence.content, default=str) if not isinstance(evidence.content, str) else evidence.content
        current_hash = hashlib.sha256(content_str.encode()).hexdigest()
        
        return current_hash == evidence.content_hash
