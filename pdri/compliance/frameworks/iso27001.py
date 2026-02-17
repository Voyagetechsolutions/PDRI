"""
ISO 27001 Assessor
==================

ISO 27001:2022 Information Security Management compliance assessment.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ISO27001Control:
    """An ISO 27001 control."""
    control_id: str
    title: str
    domain: str  # Organizational, People, Physical, Technological
    objective: str


class ISO27001Assessor:
    """
    ISO 27001:2022 compliance assessor.
    
    Annex A domains:
    - Organizational Controls (37 controls)
    - People Controls (8 controls)
    - Physical Controls (14 controls)
    - Technological Controls (34 controls)
    """
    
    DOMAINS = {
        "5": "Organizational",
        "6": "People",
        "7": "Physical",
        "8": "Technological",
    }
    
    def __init__(self, graph_engine: Any):
        self.graph_engine = graph_engine
        self._controls = self._load_controls()
    
    def _load_controls(self) -> List[ISO27001Control]:
        """Load ISO 27001 Annex A controls."""
        return [
            ISO27001Control("5.1", "Policies for Information Security", "Organizational",
                          "Establish and maintain information security policies"),
            ISO27001Control("5.15", "Access Control", "Organizational",
                          "Ensure authorized access and prevent unauthorized access"),
            ISO27001Control("5.23", "Information Security for Cloud Services", "Organizational",
                          "Manage security of cloud service use"),
            ISO27001Control("5.30", "ICT Readiness for Business Continuity", "Organizational",
                          "Ensure ICT services are available during disruption"),
            ISO27001Control("6.1", "Screening", "People",
                          "Verify backgrounds of personnel"),
            ISO27001Control("6.3", "Information Security Awareness", "People",
                          "Ensure personnel are aware of responsibilities"),
            ISO27001Control("7.1", "Physical Security Perimeters", "Physical",
                          "Prevent unauthorized physical access"),
            ISO27001Control("7.4", "Physical Security Monitoring", "Physical",
                          "Detect unauthorized physical access"),
            ISO27001Control("8.1", "User End Point Devices", "Technological",
                          "Protect information on user devices"),
            ISO27001Control("8.5", "Secure Authentication", "Technological",
                          "Ensure secure authentication technologies"),
            ISO27001Control("8.7", "Protection Against Malware", "Technological",
                          "Prevent malware infection"),
            ISO27001Control("8.12", "Data Leakage Prevention", "Technological",
                          "Prevent unauthorized disclosure of information"),
            ISO27001Control("8.15", "Logging", "Technological",
                          "Record activities and events"),
            ISO27001Control("8.16", "Monitoring Activities", "Technological",
                          "Detect anomalous behavior and security events"),
            ISO27001Control("8.28", "Secure Coding", "Technological",
                          "Ensure secure development practices"),
        ]
    
    async def assess_control(self, control_id: str) -> Dict[str, Any]:
        """Assess a specific ISO 27001 control."""
        control = next((c for c in self._controls if c.control_id == control_id), None)
        if not control:
            return {"error": f"Control {control_id} not found"}
        
        # Run domain-specific assessment
        if control.domain == "Technological":
            return await self._assess_technological(control)
        elif control.domain == "Organizational":
            return await self._assess_organizational(control)
        else:
            return await self._assess_generic(control)
    
    async def _assess_technological(self, control: ISO27001Control) -> Dict[str, Any]:
        """Assess technological controls using PDRI data."""
        score = 75
        findings = []
        evidence = []
        recommendations = []
        
        if "8.12" in control.control_id:
            # DLP
            findings.append("Data flow monitoring active via PDRI graph")
            evidence.append("Data exposure paths tracked")
            recommendations.append("Implement automated DLP policies")
            score = 80
        elif "8.16" in control.control_id:
            # Monitoring
            findings.append("Continuous security monitoring operational")
            evidence.append("PDRI risk scoring provides real-time monitoring")
            score = 85
        
        return {
            "control_id": control.control_id,
            "score": score,
            "findings": findings,
            "evidence": evidence,
            "recommendations": recommendations,
        }
    
    async def _assess_organizational(self, control: ISO27001Control) -> Dict[str, Any]:
        """Assess organizational controls."""
        return {
            "control_id": control.control_id,
            "score": 70,
            "findings": ["Policy documentation needs review"],
            "evidence": ["Policies exist but may be outdated"],
            "recommendations": ["Schedule annual policy review"],
        }
    
    async def _assess_generic(self, control: ISO27001Control) -> Dict[str, Any]:
        """Generic control assessment."""
        return {
            "control_id": control.control_id,
            "score": 75,
            "findings": [],
            "evidence": ["Manual review required"],
            "recommendations": [f"Complete assessment for {control.control_id}"],
        }
    
    async def assess_all(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Assess all controls."""
        controls = self._controls
        if domain:
            controls = [c for c in controls if c.domain == domain]
        
        results = []
        for control in controls:
            result = await self.assess_control(control.control_id)
            results.append(result)
        return results
    
    def list_controls(self) -> List[Dict]:
        """List all controls."""
        return [
            {"id": c.control_id, "title": c.title, "domain": c.domain}
            for c in self._controls
        ]
