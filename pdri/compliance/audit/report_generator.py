"""
Compliance Report Generator
============================

Generate compliance reports for auditors and stakeholders.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json


@dataclass
class ReportSection:
    """A section of a compliance report."""
    title: str
    content: str
    findings: List[str]
    recommendations: List[str]
    evidence_refs: List[str]


@dataclass
class ComplianceReport:
    """A complete compliance report."""
    report_id: str
    title: str
    framework: str
    scope: str
    generated_at: datetime
    generated_by: str
    executive_summary: str
    sections: List[ReportSection]
    overall_score: float
    overall_status: str
    evidence_count: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "framework": self.framework,
            "scope": self.scope,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "executive_summary": self.executive_summary,
            "sections": [
                {
                    "title": s.title,
                    "content": s.content,
                    "findings": s.findings,
                    "recommendations": s.recommendations,
                    "evidence_refs": s.evidence_refs,
                }
                for s in self.sections
            ],
            "overall_score": self.overall_score,
            "overall_status": self.overall_status,
            "evidence_count": self.evidence_count,
        }
    
    def to_markdown(self) -> str:
        """Generate markdown version of report."""
        lines = [
            f"# {self.title}",
            "",
            f"**Framework:** {self.framework}",
            f"**Scope:** {self.scope}",
            f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Overall Score:** {self.overall_score:.1f}%",
            f"**Status:** {self.overall_status}",
            "",
            "## Executive Summary",
            "",
            self.executive_summary,
            "",
        ]
        
        for section in self.sections:
            lines.append(f"## {section.title}")
            lines.append("")
            lines.append(section.content)
            lines.append("")
            
            if section.findings:
                lines.append("### Findings")
                for finding in section.findings:
                    lines.append(f"- {finding}")
                lines.append("")
            
            if section.recommendations:
                lines.append("### Recommendations")
                for rec in section.recommendations:
                    lines.append(f"- {rec}")
                lines.append("")
            
            if section.evidence_refs:
                lines.append("### Evidence")
                for ref in section.evidence_refs:
                    lines.append(f"- {ref}")
                lines.append("")
        
        return "\n".join(lines)


class ComplianceReportGenerator:
    """
    Generate compliance reports from assessment data.
    
    Report types:
    - Executive summary
    - Detailed technical report
    - Gap analysis
    - Remediation plan
    
    Example:
        generator = ComplianceReportGenerator()
        report = generator.generate(assessment, evidence)
        markdown = report.to_markdown()
    """
    
    def __init__(self):
        self._report_counter = 0
    
    def generate(
        self,
        assessment: Any,  # ComplianceAssessment
        evidence: Dict[str, List[Any]] = None,
        report_type: str = "detailed"
    ) -> ComplianceReport:
        """
        Generate compliance report.
        
        Args:
            assessment: ComplianceAssessment object
            evidence: Evidence by control ID
            report_type: Type of report (detailed, executive, gap)
        
        Returns:
            ComplianceReport object
        """
        self._report_counter += 1
        report_id = f"rpt-{self._report_counter:06d}"
        
        # Extract assessment data
        framework = assessment.framework.value if hasattr(assessment.framework, 'value') else str(assessment.framework)
        overall_score = assessment.overall_score
        overall_status = assessment.overall_status.value if hasattr(assessment.overall_status, 'value') else str(assessment.overall_status)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(assessment)
        
        # Generate sections
        if report_type == "executive":
            sections = self._generate_executive_sections(assessment)
        elif report_type == "gap":
            sections = self._generate_gap_sections(assessment)
        else:
            sections = self._generate_detailed_sections(assessment, evidence or {})
        
        # Count evidence
        evidence_count = sum(len(e) for e in (evidence or {}).values())
        
        return ComplianceReport(
            report_id=report_id,
            title=f"{framework.upper()} Compliance Assessment Report",
            framework=framework,
            scope=assessment.scope,
            generated_at=datetime.now(timezone.utc),
            generated_by="pdri-report-generator",
            executive_summary=executive_summary,
            sections=sections,
            overall_score=overall_score,
            overall_status=overall_status,
            evidence_count=evidence_count,
        )
    
    def _generate_executive_summary(self, assessment: Any) -> str:
        """Generate executive summary."""
        framework = assessment.framework.value if hasattr(assessment.framework, 'value') else str(assessment.framework)
        
        compliant = assessment.compliant_count
        non_compliant = assessment.non_compliant_count
        total = len(assessment.control_assessments)
        
        summary = (
            f"This {framework.upper()} compliance assessment evaluated {total} controls "
            f"across the defined scope. The overall compliance score is {assessment.overall_score:.1f}%. "
            f"{compliant} controls are fully compliant, while {non_compliant} controls require remediation. "
        )
        
        if assessment.overall_score >= 90:
            summary += "The organization demonstrates strong compliance posture."
        elif assessment.overall_score >= 70:
            summary += "Areas for improvement have been identified and should be addressed."
        else:
            summary += "Significant gaps exist that require immediate attention."
        
        return summary
    
    def _generate_detailed_sections(
        self,
        assessment: Any,
        evidence: Dict[str, List[Any]]
    ) -> List[ReportSection]:
        """Generate detailed report sections."""
        sections = []
        
        # Overview section
        sections.append(ReportSection(
            title="Assessment Overview",
            content=f"Assessment performed on {assessment.started_at.strftime('%Y-%m-%d')} "
                   f"covering {len(assessment.control_assessments)} controls.",
            findings=[],
            recommendations=[],
            evidence_refs=[],
        ))
        
        # Group controls by status
        non_compliant = [c for c in assessment.control_assessments 
                        if c.status.value == "non_compliant"]
        partial = [c for c in assessment.control_assessments 
                  if c.status.value == "partially_compliant"]
        compliant = [c for c in assessment.control_assessments 
                    if c.status.value == "compliant"]
        
        # Non-compliant section
        if non_compliant:
            findings = []
            recommendations = []
            evidence_refs = []
            
            for ctrl in non_compliant:
                findings.extend(ctrl.findings or [f"{ctrl.control_id}: Non-compliant"])
                recommendations.extend(ctrl.recommendations or [])
                evidence_refs.extend([e.evidence_id for e in evidence.get(ctrl.control_id, [])])
            
            sections.append(ReportSection(
                title="Non-Compliant Controls (Immediate Action Required)",
                content=f"{len(non_compliant)} controls failed compliance requirements.",
                findings=findings[:20],
                recommendations=recommendations[:10],
                evidence_refs=evidence_refs[:10],
            ))
        
        # Partially compliant section
        if partial:
            sections.append(ReportSection(
                title="Partially Compliant Controls",
                content=f"{len(partial)} controls require minor improvements.",
                findings=[f"{c.control_id}: {c.control_name}" for c in partial[:10]],
                recommendations=["Complete implementation of partial controls"],
                evidence_refs=[],
            ))
        
        # Compliant section
        if compliant:
            sections.append(ReportSection(
                title="Compliant Controls",
                content=f"{len(compliant)} controls meet all requirements.",
                findings=[],
                recommendations=["Continue monitoring and periodic reassessment"],
                evidence_refs=[],
            ))
        
        return sections
    
    def _generate_executive_sections(self, assessment: Any) -> List[ReportSection]:
        """Generate executive summary sections."""
        return [
            ReportSection(
                title="Key Metrics",
                content=f"Overall Score: {assessment.overall_score:.1f}%",
                findings=[
                    f"Compliant Controls: {assessment.compliant_count}",
                    f"Non-Compliant Controls: {assessment.non_compliant_count}",
                ],
                recommendations=[],
                evidence_refs=[],
            ),
            ReportSection(
                title="Next Steps",
                content="Prioritized remediation activities.",
                findings=[],
                recommendations=[
                    "Address critical control gaps within 30 days",
                    "Schedule follow-up assessment in 90 days",
                ],
                evidence_refs=[],
            ),
        ]
    
    def _generate_gap_sections(self, assessment: Any) -> List[ReportSection]:
        """Generate gap analysis sections."""
        gaps = [c for c in assessment.control_assessments 
                if c.status.value in ("non_compliant", "partially_compliant")]
        
        sections = []
        
        for gap in gaps[:20]:  # Limit to 20 gaps
            sections.append(ReportSection(
                title=f"Gap: {gap.control_id} - {gap.control_name}",
                content=f"Current Score: {gap.score:.0f}%",
                findings=gap.findings or ["Compliance gap identified"],
                recommendations=gap.recommendations or ["Implement control requirements"],
                evidence_refs=gap.evidence,
            ))
        
        return sections
    
    def generate_batch(
        self,
        assessments: List[Any],
        evidence: Dict[str, Dict[str, List[Any]]] = None
    ) -> List[ComplianceReport]:
        """Generate reports for multiple assessments."""
        reports = []
        for assessment in assessments:
            assessment_evidence = (evidence or {}).get(assessment.assessment_id, {})
            report = self.generate(assessment, assessment_evidence)
            reports.append(report)
        return reports
    
    def export_report(
        self,
        report: ComplianceReport,
        format: str = "json"
    ) -> str:
        """Export report to format."""
        if format == "json":
            return json.dumps(report.to_dict(), indent=2)
        elif format == "markdown":
            return report.to_markdown()
        else:
            raise ValueError(f"Unknown format: {format}")
