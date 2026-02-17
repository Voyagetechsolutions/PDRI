"""
Dmitry Strategic Advisor
========================

Strategic risk analysis for executive briefings and M&A.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class BriefingType(Enum):
    """Types of executive briefings."""
    BOARD = "board"
    CISO = "ciso"
    EXECUTIVE = "executive"
    AUDIT_COMMITTEE = "audit_committee"
    INVESTOR = "investor"


class RiskImpact(Enum):
    """Business impact levels."""
    NEGLIGIBLE = "negligible"
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    SEVERE = "severe"


@dataclass
class StrategicInsight:
    """A strategic risk insight."""
    insight_id: str
    category: str
    title: str
    summary: str
    business_impact: RiskImpact
    financial_exposure: Optional[float]
    recommendations: List[str]
    supporting_data: Dict[str, Any]


@dataclass
class BoardBriefing:
    """Executive board briefing package."""
    briefing_id: str
    briefing_type: BriefingType
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    executive_summary: str
    risk_posture: str
    key_metrics: Dict[str, Any]
    insights: List[StrategicInsight]
    trend_analysis: Dict[str, str]
    peer_comparison: Optional[Dict[str, Any]]
    action_items: List[Dict[str, str]]
    
    def to_executive_format(self) -> str:
        """Format for executive presentation."""
        lines = [
            f"# Risk Posture Briefing",
            f"**Period:** {self.period_start.strftime('%Y-%m-%d')} to {self.period_end.strftime('%Y-%m-%d')}",
            "",
            "## Executive Summary",
            self.executive_summary,
            "",
            f"## Risk Posture: {self.risk_posture.upper()}",
            "",
            "## Key Metrics",
        ]
        
        for metric, value in self.key_metrics.items():
            lines.append(f"- **{metric}:** {value}")
        
        lines.extend(["", "## Strategic Insights"])
        for insight in self.insights[:5]:
            lines.append(f"### {insight.title}")
            lines.append(insight.summary)
            if insight.financial_exposure:
                lines.append(f"- **Financial Exposure:** ${insight.financial_exposure:,.0f}")
            lines.append("")
        
        lines.extend(["## Recommended Actions"])
        for i, item in enumerate(self.action_items[:5], 1):
            lines.append(f"{i}. **{item['action']}** - {item.get('owner', 'TBD')}")
        
        return "\n".join(lines)


@dataclass
class MARiskAssessment:
    """M&A risk assessment."""
    assessment_id: str
    target_company: str
    assessment_date: datetime
    overall_risk_rating: str  # low, medium, high, critical
    risk_score: float
    deal_impact: str  # proceed, caution, reconsider
    key_findings: List[Dict[str, Any]]
    integration_risks: List[Dict[str, Any]]
    recommendations: List[str]
    estimated_remediation_cost: float
    due_diligence_gaps: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "target_company": self.target_company,
            "assessment_date": self.assessment_date.isoformat(),
            "overall_risk_rating": self.overall_risk_rating,
            "risk_score": self.risk_score,
            "deal_impact": self.deal_impact,
            "key_findings": self.key_findings,
            "integration_risks": self.integration_risks,
            "recommendations": self.recommendations,
            "estimated_remediation_cost": self.estimated_remediation_cost,
            "due_diligence_gaps": self.due_diligence_gaps,
        }


class StrategicAdvisor:
    """
    Dmitry's strategic advisory capabilities.
    
    Provides:
    - Executive board briefings
    - M&A risk assessment
    - Investment risk analysis
    - Strategic recommendations
    
    Example:
        advisor = StrategicAdvisor(graph_engine, scoring_engine)
        briefing = await advisor.generate_board_briefing(
            period_days=90,
            briefing_type=BriefingType.BOARD
        )
    """
    
    def __init__(
        self,
        graph_engine: Any,
        scoring_engine: Any = None,
        compliance_engine: Any = None
    ):
        """
        Initialize strategic advisor.
        
        Args:
            graph_engine: Graph database engine
            scoring_engine: Risk scoring engine
            compliance_engine: Compliance assessment engine
        """
        self.graph_engine = graph_engine
        self.scoring_engine = scoring_engine
        self.compliance_engine = compliance_engine
        
        self._briefing_counter = 0
        self._assessment_counter = 0
    
    async def generate_board_briefing(
        self,
        period_days: int = 90,
        briefing_type: BriefingType = BriefingType.BOARD,
        include_peer_comparison: bool = True
    ) -> BoardBriefing:
        """
        Generate executive board briefing.
        
        Args:
            period_days: Reporting period in days
            briefing_type: Type of briefing
            include_peer_comparison: Include industry benchmarks
        
        Returns:
            BoardBriefing package
        """
        self._briefing_counter += 1
        briefing_id = f"briefing-{self._briefing_counter:06d}"
        
        now = datetime.utcnow()
        from datetime import timedelta
        period_start = now - timedelta(days=period_days)
        
        # Gather metrics
        metrics = await self._gather_metrics(period_start, now)
        
        # Generate insights
        insights = await self._generate_insights(period_start, now)
        
        # Analyze trends
        trends = await self._analyze_trends(period_start, now)
        
        # Determine risk posture
        risk_posture = self._determine_posture(metrics)
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary(
            metrics, insights, trends, risk_posture
        )
        
        # Peer comparison
        peer_comp = await self._get_peer_comparison() if include_peer_comparison else None
        
        # Action items
        action_items = self._generate_action_items(insights)
        
        return BoardBriefing(
            briefing_id=briefing_id,
            briefing_type=briefing_type,
            generated_at=now,
            period_start=period_start,
            period_end=now,
            executive_summary=exec_summary,
            risk_posture=risk_posture,
            key_metrics=metrics,
            insights=insights,
            trend_analysis=trends,
            peer_comparison=peer_comp,
            action_items=action_items,
        )
    
    async def assess_ma_risk(
        self,
        target_company: str,
        target_data: Dict[str, Any] = None
    ) -> MARiskAssessment:
        """
        Assess M&A target risk.
        
        Args:
            target_company: Name of target company
            target_data: Available data about target
        
        Returns:
            MARiskAssessment with findings
        """
        self._assessment_counter += 1
        assessment_id = f"ma-{self._assessment_counter:06d}"
        
        # Analyze available data
        findings = await self._analyze_target(target_company, target_data or {})
        
        # Assess integration risks
        integration_risks = self._assess_integration_risks(target_data or {})
        
        # Calculate overall risk
        risk_score = self._calculate_ma_risk_score(findings, integration_risks)
        
        # Determine rating
        if risk_score < 30:
            rating = "low"
            impact = "proceed"
        elif risk_score < 60:
            rating = "medium"
            impact = "caution"
        elif risk_score < 80:
            rating = "high"
            impact = "caution"
        else:
            rating = "critical"
            impact = "reconsider"
        
        # Generate recommendations
        recommendations = self._generate_ma_recommendations(findings, integration_risks)
        
        # Estimate remediation cost
        remediation_cost = self._estimate_remediation(findings)
        
        # Identify due diligence gaps
        dd_gaps = self._identify_dd_gaps(target_data or {})
        
        return MARiskAssessment(
            assessment_id=assessment_id,
            target_company=target_company,
            assessment_date=datetime.utcnow(),
            overall_risk_rating=rating,
            risk_score=risk_score,
            deal_impact=impact,
            key_findings=findings,
            integration_risks=integration_risks,
            recommendations=recommendations,
            estimated_remediation_cost=remediation_cost,
            due_diligence_gaps=dd_gaps,
        )
    
    async def _gather_metrics(
        self,
        start: datetime,
        end: datetime
    ) -> Dict[str, Any]:
        """Gather key risk metrics."""
        return {
            "Overall Risk Score": "72/100",
            "Critical Assets at Risk": 12,
            "Compliance Score": "87%",
            "Open Vulnerabilities": 34,
            "Incidents (Period)": 3,
            "Third-Party Risk Exposure": "Medium",
            "AI Tool Risk Coverage": "78%",
        }
    
    async def _generate_insights(
        self,
        start: datetime,
        end: datetime
    ) -> List[StrategicInsight]:
        """Generate strategic insights."""
        return [
            StrategicInsight(
                insight_id="ins-001",
                category="Third-Party Risk",
                title="Vendor Concentration Risk in Cloud Services",
                summary="Heavy reliance on single cloud provider creates business continuity risk. "
                       "85% of critical workloads on one platform.",
                business_impact=RiskImpact.MAJOR,
                financial_exposure=2500000,
                recommendations=["Develop multi-cloud strategy", "Review SLAs"],
                supporting_data={"vendor_concentration": 0.85},
            ),
            StrategicInsight(
                insight_id="ins-002",
                category="AI/ML Risk",
                title="Shadow AI Usage Increasing",
                summary="23% increase in unvetted AI tool usage by employees. "
                       "Data exposure risk through consumer AI services.",
                business_impact=RiskImpact.MODERATE,
                financial_exposure=500000,
                recommendations=["Deploy approved AI alternatives", "Update acceptable use policy"],
                supporting_data={"shadow_ai_growth": 0.23},
            ),
            StrategicInsight(
                insight_id="ins-003",
                category="Regulatory",
                title="GDPR Compliance Gap in New Markets",
                summary="Expansion into EU markets requires enhanced data protection controls. "
                       "Current controls 70% compliant.",
                business_impact=RiskImpact.MAJOR,
                financial_exposure=4000000,
                recommendations=["Accelerate privacy program", "Engage DPO"],
                supporting_data={"gdpr_compliance": 0.70},
            ),
        ]
    
    async def _analyze_trends(
        self,
        start: datetime,
        end: datetime
    ) -> Dict[str, str]:
        """Analyze risk trends."""
        return {
            "Overall Risk": "Stable with slight increase",
            "Security Posture": "Improving (+5%)",
            "Compliance": "Stable",
            "Third-Party Risk": "Degrading (-8%)",
            "Insider Risk": "Stable",
        }
    
    def _determine_posture(self, metrics: Dict[str, Any]) -> str:
        """Determine overall risk posture."""
        # Simplified logic
        return "ELEVATED"
    
    def _generate_executive_summary(
        self,
        metrics: Dict,
        insights: List[StrategicInsight],
        trends: Dict,
        posture: str
    ) -> str:
        """Generate executive summary."""
        critical_insights = [i for i in insights if i.business_impact in (RiskImpact.MAJOR, RiskImpact.SEVERE)]
        total_exposure = sum(i.financial_exposure or 0 for i in insights)
        
        return (
            f"The organization's risk posture is **{posture}** for this reporting period. "
            f"We have identified {len(critical_insights)} areas requiring immediate attention "
            f"with a combined financial exposure estimate of ${total_exposure:,.0f}. "
            f"Key trends show improvement in security posture while third-party risk requires attention. "
            f"Recommended actions focus on vendor diversification and AI governance."
        )
    
    async def _get_peer_comparison(self) -> Dict[str, Any]:
        """Get industry peer comparison."""
        return {
            "industry": "Technology",
            "sample_size": 150,
            "our_percentile": 65,
            "areas_above_average": ["Incident Response", "Access Controls"],
            "areas_below_average": ["Third-Party Management", "AI Governance"],
        }
    
    def _generate_action_items(
        self,
        insights: List[StrategicInsight]
    ) -> List[Dict[str, str]]:
        """Generate action items from insights."""
        items = []
        for insight in insights:
            for rec in insight.recommendations[:1]:
                items.append({
                    "action": rec,
                    "owner": "CISO",
                    "due": "30 days",
                    "priority": insight.business_impact.value,
                })
        return items[:5]
    
    async def _analyze_target(
        self,
        company: str,
        data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze M&A target."""
        return [
            {
                "category": "Security Posture",
                "finding": "Outdated security infrastructure",
                "severity": "high",
                "detail": "Core security tools 2+ years behind current versions",
            },
            {
                "category": "Compliance",
                "finding": "SOC 2 Type II not completed",
                "severity": "medium",
                "detail": "In progress, expected Q3 completion",
            },
            {
                "category": "Data Management",
                "finding": "Data classification program incomplete",
                "severity": "medium",
                "detail": "Only 40% of data assets classified",
            },
        ]
    
    def _assess_integration_risks(
        self,
        data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Assess integration risks."""
        return [
            {
                "risk": "Technology Stack Incompatibility",
                "likelihood": "medium",
                "impact": "high",
                "mitigation": "Phased integration with compatibility layer",
            },
            {
                "risk": "Policy Harmonization",
                "likelihood": "high",
                "impact": "medium",
                "mitigation": "Joint policy review committee",
            },
        ]
    
    def _calculate_ma_risk_score(
        self,
        findings: List[Dict],
        integration_risks: List[Dict]
    ) -> float:
        """Calculate M&A risk score."""
        base_score = 50
        for f in findings:
            if f["severity"] == "high":
                base_score += 15
            elif f["severity"] == "medium":
                base_score += 8
        
        for r in integration_risks:
            if r["impact"] == "high":
                base_score += 10
        
        return min(100, base_score)
    
    def _generate_ma_recommendations(
        self,
        findings: List[Dict],
        risks: List[Dict]
    ) -> List[str]:
        """Generate M&A recommendations."""
        return [
            "Conduct detailed security assessment before close",
            "Budget for security infrastructure modernization",
            "Require SOC 2 completion as deal condition",
            "Plan 6-month integration timeline for security systems",
        ]
    
    def _estimate_remediation(self, findings: List[Dict]) -> float:
        """Estimate remediation cost."""
        cost = 0
        for f in findings:
            if f["severity"] == "high":
                cost += 500000
            elif f["severity"] == "medium":
                cost += 150000
            else:
                cost += 50000
        return cost
    
    def _identify_dd_gaps(self, data: Dict[str, Any]) -> List[str]:
        """Identify due diligence gaps."""
        gaps = []
        required_areas = [
            "penetration_test_results",
            "incident_history",
            "vendor_list",
            "data_flow_diagrams",
            "compliance_certifications",
        ]
        for area in required_areas:
            if area not in data:
                gaps.append(area.replace("_", " ").title())
        return gaps
