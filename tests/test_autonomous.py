"""
PDRI Test Suite - Autonomous Module
====================================

Tests for autonomous risk management.

Author: PDRI Team
Version: 1.0.0
"""

import pytest
from datetime import datetime


class TestAutonomousManager:
    """Tests for autonomous risk manager."""
    
    def test_initialization(self):
        """Test manager initialization."""
        from pdri.autonomous.manager import (
            AutonomousRiskManager, MonitoringConfig, RiskThreshold
        )
        
        config = MonitoringConfig(
            check_interval_seconds=30,
            auto_remediate=False,
        )
        thresholds = RiskThreshold(
            elevated=60,
            high=75,
            critical=85,
            emergency=95,
        )
        
        manager = AutonomousRiskManager(
            graph_engine=None,
            scoring_engine=None,
            config=config,
            thresholds=thresholds,
        )
        
        stats = manager.get_statistics()
        assert stats["monitoring_active"] is False
        assert stats["config"]["check_interval"] == 30
    
    def test_determine_state(self):
        """Test risk state determination."""
        from pdri.autonomous.manager import (
            AutonomousRiskManager, RiskState
        )
        
        manager = AutonomousRiskManager(
            graph_engine=None,
            scoring_engine=None,
        )
        
        assert manager._determine_state(50) == RiskState.NORMAL
        assert manager._determine_state(65) == RiskState.ELEVATED
        assert manager._determine_state(80) == RiskState.HIGH
        assert manager._determine_state(90) == RiskState.CRITICAL
        assert manager._determine_state(98) == RiskState.EMERGENCY
    
    def test_callback_registration(self):
        """Test callback registration."""
        from pdri.autonomous.manager import (
            AutonomousRiskManager, RiskState
        )
        
        manager = AutonomousRiskManager(
            graph_engine=None,
            scoring_engine=None,
        )
        
        callback_called = []
        
        async def test_callback(event):
            callback_called.append(event)
        
        manager.register_callback(RiskState.CRITICAL, test_callback)
        
        assert len(manager._callbacks[RiskState.CRITICAL]) == 1


class TestResponseEngine:
    """Tests for response engine."""
    
    @pytest.mark.asyncio
    async def test_execute_alert(self):
        """Test executing an alert action."""
        from pdri.autonomous.response_engine import (
            ResponseEngine, ResponseStatus, ResponsePriority
        )
        
        engine = ResponseEngine()
        action = await engine.execute(
            action_type="alert",
            target_id="node-123",
            priority=ResponsePriority.HIGH,
        )
        
        assert action.status == ResponseStatus.COMPLETED
        assert action.result["alerted"] is True
    
    @pytest.mark.asyncio
    async def test_pending_approval(self):
        """Test action pending approval."""
        from pdri.autonomous.response_engine import (
            ResponseEngine, ResponseStatus
        )
        
        engine = ResponseEngine()
        action = await engine.execute(
            action_type="isolate",
            target_id="node-456",
            requires_approval=True,
        )
        
        assert action.status == ResponseStatus.PENDING
        
        pending = engine.get_pending_approvals()
        assert len(pending) == 1
    
    @pytest.mark.asyncio
    async def test_approve_action(self):
        """Test approving a pending action."""
        from pdri.autonomous.response_engine import (
            ResponseEngine, ResponseStatus
        )
        
        engine = ResponseEngine()
        action = await engine.execute(
            action_type="restrict",
            target_id="node-789",
            requires_approval=True,
        )
        
        approved = await engine.approve_action(
            action.action_id,
            approved_by="admin@example.com"
        )
        
        assert approved.status == ResponseStatus.COMPLETED
        assert approved.approved_by == "admin@example.com"
    
    def test_statistics(self):
        """Test response engine statistics."""
        from pdri.autonomous.response_engine import ResponseEngine
        
        engine = ResponseEngine()
        stats = engine.get_statistics()
        
        assert "total_actions" in stats
        assert "registered_handlers" in stats
        assert "alert" in stats["registered_handlers"]


class TestStrategicAdvisor:
    """Tests for Dmitry strategic advisor."""
    
    @pytest.mark.asyncio
    async def test_board_briefing(self):
        """Test generating board briefing."""
        from dmitry.tools.strategic_advisor import (
            StrategicAdvisor, BriefingType
        )
        
        advisor = StrategicAdvisor(graph_engine=None)
        briefing = await advisor.generate_board_briefing(
            period_days=90,
            briefing_type=BriefingType.BOARD,
        )
        
        assert briefing.briefing_id.startswith("briefing-")
        assert briefing.risk_posture in ("NORMAL", "ELEVATED", "HIGH", "CRITICAL")
        assert len(briefing.insights) > 0
    
    @pytest.mark.asyncio
    async def test_ma_assessment(self):
        """Test M&A risk assessment."""
        from dmitry.tools.strategic_advisor import StrategicAdvisor
        
        advisor = StrategicAdvisor(graph_engine=None)
        assessment = await advisor.assess_ma_risk(
            target_company="Target Corp",
            target_data={},
        )
        
        assert assessment.assessment_id.startswith("ma-")
        assert assessment.target_company == "Target Corp"
        assert assessment.deal_impact in ("proceed", "caution", "reconsider")
    
    @pytest.mark.asyncio
    async def test_briefing_format(self):
        """Test executive briefing format."""
        from dmitry.tools.strategic_advisor import (
            StrategicAdvisor, BriefingType
        )
        
        advisor = StrategicAdvisor(graph_engine=None)
        briefing = await advisor.generate_board_briefing()
        
        formatted = briefing.to_executive_format()
        assert "# Risk Posture Briefing" in formatted
        assert "## Executive Summary" in formatted
