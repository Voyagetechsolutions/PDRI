"""
Compliance Engine
=================

Core engine for compliance assessment across multiple frameworks.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import json


class ComplianceStatus(Enum):
    """Compliance status for controls."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING_REVIEW = "pending_review"


class FrameworkType(Enum):
    """Supported compliance frameworks."""
    FEDRAMP = "fedramp"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    NIST_CSF = "nist_csf"
    PCI_DSS = "pci_dss"


@dataclass
class ControlAssessment:
    """Assessment of a single compliance control."""
    control_id: str
    control_name: str
    framework: FrameworkType
    status: ComplianceStatus
    score: float  # 0-100
    findings: List[str]
    evidence: List[str]
    recommendations: List[str]
    assessed_at: datetime
    assessed_by: str = "pdri-automated"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "framework": self.framework.value,
            "status": self.status.value,
            "score": self.score,
            "findings": self.findings,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "assessed_at": self.assessed_at.isoformat(),
            "assessed_by": self.assessed_by,
        }


@dataclass
class ComplianceAssessment:
    """Complete compliance assessment for a framework."""
    assessment_id: str
    framework: FrameworkType
    scope: str
    started_at: datetime
    completed_at: Optional[datetime]
    control_assessments: List[ControlAssessment]
    overall_score: float
    overall_status: ComplianceStatus
    summary: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "framework": self.framework.value,
            "scope": self.scope,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "control_assessments": [c.to_dict() for c in self.control_assessments],
            "overall_score": self.overall_score,
            "overall_status": self.overall_status.value,
            "summary": self.summary,
        }
    
    @property
    def compliant_count(self) -> int:
        return len([c for c in self.control_assessments if c.status == ComplianceStatus.COMPLIANT])
    
    @property
    def non_compliant_count(self) -> int:
        return len([c for c in self.control_assessments if c.status == ComplianceStatus.NON_COMPLIANT])


class ComplianceEngine:
    """
    Core compliance assessment engine.
    
    Evaluates PDRI data against multiple compliance frameworks:
    - FedRAMP: Federal Risk and Authorization Management Program
    - SOC 2: Service Organization Control 2
    - ISO 27001: Information Security Management
    - GDPR: General Data Protection Regulation
    - HIPAA: Health Insurance Portability and Accountability Act
    
    Example:
        engine = ComplianceEngine(graph_engine)
        assessment = await engine.assess(FrameworkType.SOC2, scope="all")
        print(f"Score: {assessment.overall_score}%")
    """
    
    def __init__(
        self,
        graph_engine: Any,
        scoring_engine: Any = None
    ):
        self.graph_engine = graph_engine
        self.scoring_engine = scoring_engine
        self._assessment_counter = 0
        
        # Load framework definitions
        self._frameworks = self._load_frameworks()
    
    def _load_frameworks(self) -> Dict[FrameworkType, Dict]:
        """Load framework control definitions."""
        # In production, these would be loaded from files/database
        return {
            FrameworkType.FEDRAMP: self._fedramp_controls(),
            FrameworkType.SOC2: self._soc2_controls(),
            FrameworkType.ISO27001: self._iso27001_controls(),
            FrameworkType.GDPR: self._gdpr_controls(),
            FrameworkType.HIPAA: self._hipaa_controls(),
        }
    
    async def assess(
        self,
        framework: FrameworkType,
        scope: str = "all",
        control_ids: Optional[List[str]] = None
    ) -> ComplianceAssessment:
        """
        Run compliance assessment.
        
        Args:
            framework: Framework to assess against
            scope: Scope of assessment
            control_ids: Specific controls to assess (all if None)
        
        Returns:
            ComplianceAssessment with results
        """
        self._assessment_counter += 1
        assessment_id = f"assess-{self._assessment_counter:06d}"
        started_at = datetime.utcnow()
        
        # Get framework controls
        framework_def = self._frameworks.get(framework, {})
        controls = framework_def.get("controls", [])
        
        if control_ids:
            controls = [c for c in controls if c["id"] in control_ids]
        
        # Assess each control
        control_assessments = []
        for control in controls:
            assessment = await self._assess_control(framework, control)
            control_assessments.append(assessment)
        
        # Calculate overall score
        if control_assessments:
            overall_score = sum(c.score for c in control_assessments) / len(control_assessments)
        else:
            overall_score = 0.0
        
        # Determine overall status
        if overall_score >= 90:
            overall_status = ComplianceStatus.COMPLIANT
        elif overall_score >= 70:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT
        
        # Generate summary
        summary = self._generate_summary(framework, control_assessments, overall_score)
        
        return ComplianceAssessment(
            assessment_id=assessment_id,
            framework=framework,
            scope=scope,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            control_assessments=control_assessments,
            overall_score=overall_score,
            overall_status=overall_status,
            summary=summary,
        )
    
    async def _assess_control(
        self,
        framework: FrameworkType,
        control: Dict[str, Any]
    ) -> ControlAssessment:
        """Assess a single control."""
        control_id = control["id"]
        control_name = control["name"]
        check_function = control.get("check")
        
        findings = []
        evidence = []
        recommendations = []
        
        try:
            # Run automated check
            if check_function:
                result = await check_function(self.graph_engine, self.scoring_engine)
                score = result.get("score", 50)
                findings = result.get("findings", [])
                evidence = result.get("evidence", [])
                recommendations = result.get("recommendations", [])
            else:
                # Default scoring based on risk data
                score = await self._default_control_check(control)
        except Exception as e:
            score = 0
            findings = [f"Error assessing control: {e}"]
        
        # Determine status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 70:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ControlAssessment(
            control_id=control_id,
            control_name=control_name,
            framework=framework,
            status=status,
            score=score,
            findings=findings,
            evidence=evidence,
            recommendations=recommendations,
            assessed_at=datetime.utcnow(),
        )
    
    async def _default_control_check(self, control: Dict) -> float:
        """Default check using risk scoring."""
        # In production, would analyze graph based on control requirements
        return 75.0  # Default partially compliant
    
    def _generate_summary(
        self,
        framework: FrameworkType,
        assessments: List[ControlAssessment],
        score: float
    ) -> str:
        """Generate assessment summary."""
        compliant = len([a for a in assessments if a.status == ComplianceStatus.COMPLIANT])
        partial = len([a for a in assessments if a.status == ComplianceStatus.PARTIALLY_COMPLIANT])
        non_compliant = len([a for a in assessments if a.status == ComplianceStatus.NON_COMPLIANT])
        
        return (
            f"{framework.value.upper()} Assessment: {score:.1f}% overall compliance. "
            f"{compliant} controls compliant, {partial} partially compliant, "
            f"{non_compliant} non-compliant out of {len(assessments)} total controls."
        )
    
    # Framework control definitions
    def _fedramp_controls(self) -> Dict:
        return {
            "name": "FedRAMP",
            "version": "Rev 5",
            "controls": [
                {"id": "AC-1", "name": "Access Control Policy", "family": "Access Control"},
                {"id": "AC-2", "name": "Account Management", "family": "Access Control"},
                {"id": "AC-3", "name": "Access Enforcement", "family": "Access Control"},
                {"id": "AC-6", "name": "Least Privilege", "family": "Access Control"},
                {"id": "AU-2", "name": "Audit Events", "family": "Audit"},
                {"id": "AU-3", "name": "Content of Audit Records", "family": "Audit"},
                {"id": "CA-7", "name": "Continuous Monitoring", "family": "Assessment"},
                {"id": "CM-2", "name": "Baseline Configuration", "family": "Configuration"},
                {"id": "IA-2", "name": "Identification and Authentication", "family": "Identity"},
                {"id": "SC-7", "name": "Boundary Protection", "family": "System"},
            ],
        }
    
    def _soc2_controls(self) -> Dict:
        return {
            "name": "SOC 2 Type II",
            "version": "2024",
            "controls": [
                {"id": "CC1.1", "name": "COSO Principle 1", "category": "Security"},
                {"id": "CC2.1", "name": "Communication and Information", "category": "Security"},
                {"id": "CC3.1", "name": "Risk Assessment", "category": "Security"},
                {"id": "CC4.1", "name": "Monitoring Activities", "category": "Security"},
                {"id": "CC5.1", "name": "Control Activities", "category": "Security"},
                {"id": "CC6.1", "name": "Logical and Physical Access", "category": "Security"},
                {"id": "CC7.1", "name": "System Operations", "category": "Security"},
                {"id": "CC8.1", "name": "Change Management", "category": "Security"},
                {"id": "CC9.1", "name": "Risk Mitigation", "category": "Security"},
                {"id": "A1.1", "name": "Availability Principle", "category": "Availability"},
                {"id": "C1.1", "name": "Confidentiality Principle", "category": "Confidentiality"},
            ],
        }
    
    def _iso27001_controls(self) -> Dict:
        return {
            "name": "ISO 27001",
            "version": "2022",
            "controls": [
                {"id": "5.1", "name": "Policies for Information Security", "domain": "Organizational"},
                {"id": "5.15", "name": "Access Control", "domain": "Organizational"},
                {"id": "5.23", "name": "Information Security for Cloud Services", "domain": "Organizational"},
                {"id": "6.1", "name": "Screening", "domain": "People"},
                {"id": "7.1", "name": "Physical Security Perimeters", "domain": "Physical"},
                {"id": "8.1", "name": "User End Point Devices", "domain": "Technological"},
                {"id": "8.5", "name": "Secure Authentication", "domain": "Technological"},
                {"id": "8.12", "name": "Data Leakage Prevention", "domain": "Technological"},
                {"id": "8.15", "name": "Logging", "domain": "Technological"},
                {"id": "8.16", "name": "Monitoring Activities", "domain": "Technological"},
            ],
        }
    
    def _gdpr_controls(self) -> Dict:
        return {
            "name": "GDPR",
            "version": "2016/679",
            "controls": [
                {"id": "Art5", "name": "Principles of Processing", "article": "5"},
                {"id": "Art6", "name": "Lawfulness of Processing", "article": "6"},
                {"id": "Art7", "name": "Conditions for Consent", "article": "7"},
                {"id": "Art12", "name": "Transparent Information", "article": "12"},
                {"id": "Art17", "name": "Right to Erasure", "article": "17"},
                {"id": "Art25", "name": "Data Protection by Design", "article": "25"},
                {"id": "Art30", "name": "Records of Processing", "article": "30"},
                {"id": "Art32", "name": "Security of Processing", "article": "32"},
                {"id": "Art33", "name": "Breach Notification to Authority", "article": "33"},
                {"id": "Art35", "name": "Data Protection Impact Assessment", "article": "35"},
            ],
        }
    
    def _hipaa_controls(self) -> Dict:
        return {
            "name": "HIPAA",
            "version": "2013 Omnibus",
            "controls": [
                {"id": "164.308(a)(1)", "name": "Security Management Process", "rule": "Security"},
                {"id": "164.308(a)(3)", "name": "Workforce Security", "rule": "Security"},
                {"id": "164.308(a)(4)", "name": "Information Access Management", "rule": "Security"},
                {"id": "164.308(a)(5)", "name": "Security Awareness and Training", "rule": "Security"},
                {"id": "164.310(a)(1)", "name": "Facility Access Controls", "rule": "Security"},
                {"id": "164.310(d)(1)", "name": "Device and Media Controls", "rule": "Security"},
                {"id": "164.312(a)(1)", "name": "Access Control", "rule": "Security"},
                {"id": "164.312(b)", "name": "Audit Controls", "rule": "Security"},
                {"id": "164.312(c)(1)", "name": "Integrity", "rule": "Security"},
                {"id": "164.312(e)(1)", "name": "Transmission Security", "rule": "Security"},
                {"id": "164.502(a)", "name": "Uses and Disclosures", "rule": "Privacy"},
            ],
        }
    
    def list_frameworks(self) -> List[Dict[str, Any]]:
        """List available compliance frameworks."""
        return [
            {
                "type": ft.value,
                "name": self._frameworks[ft]["name"],
                "version": self._frameworks[ft].get("version", ""),
                "control_count": len(self._frameworks[ft].get("controls", [])),
            }
            for ft in self._frameworks
        ]
    
    async def get_control_details(
        self,
        framework: FrameworkType,
        control_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get detailed information about a control."""
        framework_def = self._frameworks.get(framework, {})
        controls = framework_def.get("controls", [])
        
        for control in controls:
            if control["id"] == control_id:
                return control
        return None
