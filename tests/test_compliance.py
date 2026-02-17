"""
PDRI Test Suite - Compliance Module
===================================

Tests for compliance framework and audit system.

Author: PDRI Team
Version: 1.0.0
"""

import pytest
from datetime import datetime


class TestAuditTrail:
    """Tests for audit trail functionality."""
    
    def test_log_event(self):
        """Test logging an audit event."""
        from pdri.compliance.audit.audit_trail import (
            AuditTrail, AuditEventType, AuditSeverity
        )
        
        trail = AuditTrail()
        event = trail.log(
            event_type=AuditEventType.DATA_ACCESS,
            actor="user@example.com",
            action="read",
            resource="customer_data",
            outcome="success",
            details={"records": 100},
        )
        
        assert event.event_id.startswith("audit-")
        assert event.actor == "user@example.com"
        assert event.outcome == "success"
        assert len(event.hash) == 64  # SHA-256
    
    def test_query_events(self):
        """Test querying audit events."""
        from pdri.compliance.audit.audit_trail import (
            AuditTrail, AuditEventType
        )
        
        trail = AuditTrail()
        trail.log(
            event_type=AuditEventType.DATA_ACCESS,
            actor="user1@example.com",
            action="read",
            resource="data",
            outcome="success",
        )
        trail.log(
            event_type=AuditEventType.AUTHENTICATION,
            actor="user2@example.com",
            action="login",
            resource="system",
            outcome="success",
        )
        
        results = trail.query(event_type=AuditEventType.DATA_ACCESS)
        assert len(results) == 1
        assert results[0].actor == "user1@example.com"
    
    def test_integrity_verification(self):
        """Test audit trail integrity verification."""
        from pdri.compliance.audit.audit_trail import (
            AuditTrail, AuditEventType
        )
        
        trail = AuditTrail()
        for i in range(5):
            trail.log(
                event_type=AuditEventType.DATA_ACCESS,
                actor=f"user{i}@example.com",
                action="read",
                resource="data",
                outcome="success",
            )
        
        assert trail.verify_integrity() is True


class TestComplianceEngine:
    """Tests for compliance assessment engine."""
    
    @pytest.mark.asyncio
    async def test_list_frameworks(self):
        """Test listing available frameworks."""
        from pdri.compliance.engine import ComplianceEngine, FrameworkType
        
        engine = ComplianceEngine(graph_engine=None)
        frameworks = engine.list_frameworks()
        
        assert len(frameworks) == 5
        framework_types = [f["type"] for f in frameworks]
        assert "fedramp" in framework_types
        assert "soc2" in framework_types
    
    @pytest.mark.asyncio
    async def test_assess_framework(self):
        """Test running a compliance assessment."""
        from pdri.compliance.engine import ComplianceEngine, FrameworkType
        
        engine = ComplianceEngine(graph_engine=None)
        assessment = await engine.assess(FrameworkType.SOC2)
        
        assert assessment.assessment_id.startswith("assess-")
        assert assessment.framework == FrameworkType.SOC2
        assert 0 <= assessment.overall_score <= 100


class TestFedRAMPAssessor:
    """Tests for FedRAMP assessor."""
    
    def test_list_controls(self):
        """Test listing FedRAMP controls."""
        from pdri.compliance.frameworks.fedramp import FedRAMPAssessor
        
        assessor = FedRAMPAssessor(graph_engine=None)
        controls = assessor.list_controls()
        
        assert len(controls) > 0
        assert any(c.control_id == "AC-2" for c in controls)
    
    @pytest.mark.asyncio
    async def test_assess_control(self):
        """Test assessing a single control."""
        from pdri.compliance.frameworks.fedramp import FedRAMPAssessor
        
        assessor = FedRAMPAssessor(graph_engine=None)
        result = await assessor.assess_control("AC-2")
        
        assert "control_id" in result
        assert "score" in result
        assert 0 <= result["score"] <= 100


class TestEvidenceCollector:
    """Tests for evidence collection."""
    
    @pytest.mark.asyncio
    async def test_collect_evidence(self):
        """Test collecting evidence for a control."""
        from pdri.compliance.audit.evidence_collector import (
            EvidenceCollector, EvidenceType
        )
        
        collector = EvidenceCollector()
        evidence = await collector.collect_for_control("AC-2", "fedramp")
        
        # Should collect at least config evidence
        assert len(evidence) >= 1
    
    def test_add_manual_evidence(self):
        """Test adding manual evidence."""
        from pdri.compliance.audit.evidence_collector import (
            EvidenceCollector, EvidenceType
        )
        
        collector = EvidenceCollector()
        evidence = collector.add_manual_evidence(
            control_id="AC-2",
            framework="fedramp",
            evidence_type=EvidenceType.ATTESTATION,
            title="Employee Training Attestation",
            description="Annual security training completed",
            content={"completion_rate": 0.98},
            collected_by="admin@example.com",
        )
        
        assert evidence.evidence_id.startswith("evd-")
        assert collector.verify_evidence(evidence.evidence_id) is True


class TestReportGenerator:
    """Tests for report generation."""
    
    def test_export_markdown(self):
        """Test exporting report to markdown."""
        from pdri.compliance.audit.report_generator import (
            ComplianceReportGenerator, ComplianceReport, ReportSection
        )
        from datetime import datetime
        
        report = ComplianceReport(
            report_id="rpt-000001",
            title="Test Report",
            framework="soc2",
            scope="all",
            generated_at=datetime.utcnow(),
            generated_by="test",
            executive_summary="Test summary",
            sections=[],
            overall_score=85.0,
            overall_status="compliant",
            evidence_count=10,
        )
        
        markdown = report.to_markdown()
        assert "# Test Report" in markdown
        assert "85.0%" in markdown
