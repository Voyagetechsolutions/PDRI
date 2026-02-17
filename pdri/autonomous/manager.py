"""
Autonomous Risk Manager
=======================

Self-monitoring and self-healing risk management.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import asyncio
import logging


class RiskState(Enum):
    """Risk monitoring states."""
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class ActionType(Enum):
    """Types of autonomous actions."""
    ALERT = "alert"
    REMEDIATE = "remediate"
    ISOLATE = "isolate"
    RESTRICT = "restrict"
    ESCALATE = "escalate"
    AUDIT = "audit"
    REPORT = "report"


@dataclass
class RiskThreshold:
    """Threshold configuration for risk levels."""
    elevated: float = 60.0
    high: float = 75.0
    critical: float = 85.0
    emergency: float = 95.0


@dataclass
class MonitoringConfig:
    """Configuration for autonomous monitoring."""
    check_interval_seconds: int = 60
    lookback_minutes: int = 15
    trend_sensitivity: float = 0.1
    auto_remediate: bool = False
    require_approval_above: float = 85.0
    max_auto_actions_per_hour: int = 10


@dataclass
class RiskEvent:
    """A detected risk event."""
    event_id: str
    timestamp: datetime
    node_id: str
    node_type: str
    risk_score: float
    previous_score: float
    risk_state: RiskState
    trend: str  # increasing, decreasing, stable
    details: Dict[str, Any]
    actions_taken: List[str] = field(default_factory=list)


class AutonomousRiskManager:
    """
    Autonomous risk monitoring and self-healing.
    
    Features:
    - Continuous risk monitoring
    - Automatic state detection
    - Policy-based response
    - Self-healing actions
    - Escalation management
    
    Example:
        manager = AutonomousRiskManager(graph_engine, scoring_engine)
        manager.start_monitoring()
        
        # Manager will automatically:
        # - Detect risk changes
        # - Trigger responses
        # - Log all actions
    """
    
    def __init__(
        self,
        graph_engine: Any,
        scoring_engine: Any,
        response_engine: Any = None,
        config: MonitoringConfig = None,
        thresholds: RiskThreshold = None
    ):
        """
        Initialize autonomous risk manager.
        
        Args:
            graph_engine: Graph database engine
            scoring_engine: Risk scoring engine
            response_engine: Optional response engine for actions
            config: Monitoring configuration
            thresholds: Risk thresholds
        """
        self.graph_engine = graph_engine
        self.scoring_engine = scoring_engine
        self.response_engine = response_engine
        self.config = config or MonitoringConfig()
        self.thresholds = thresholds or RiskThreshold()
        
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._event_counter = 0
        self._events: List[RiskEvent] = []
        self._actions_this_hour: int = 0
        self._hour_start: datetime = datetime.now(timezone.utc)
        
        self._risk_history: Dict[str, List[float]] = {}  # node_id -> scores
        self._current_states: Dict[str, RiskState] = {}
        
        self._callbacks: Dict[RiskState, List[Callable]] = {
            state: [] for state in RiskState
        }
        
        self.logger = logging.getLogger("pdri.autonomous")
    
    def start_monitoring(self) -> None:
        """Start autonomous monitoring."""
        if self._running:
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        self.logger.info("Autonomous monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop autonomous monitoring."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
        self.logger.info("Autonomous monitoring stopped")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                await self._check_all_risks()
                await asyncio.sleep(self.config.check_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _check_all_risks(self) -> None:
        """Check risks across all monitored entities."""
        # Reset hourly counter if needed
        now = datetime.now(timezone.utc)
        if (now - self._hour_start).total_seconds() > 3600:
            self._actions_this_hour = 0
            self._hour_start = now
        
        # Get high-risk nodes (mock implementation)
        high_risk_nodes = await self._get_high_risk_nodes()
        
        for node in high_risk_nodes:
            await self._process_node_risk(node)
    
    async def _get_high_risk_nodes(self) -> List[Dict[str, Any]]:
        """Get nodes with elevated risk from the graph engine."""
        if self.graph_engine is None:
            return []
        
        try:
            # Use the lowest threshold so we capture all nodes to evaluate
            nodes = await self.graph_engine.get_high_risk_nodes(
                threshold=self.thresholds.elevated / 100.0,  # Convert to 0-1 scale
                limit=100,
            )
            return nodes
        except Exception as e:
            logger.error(f"Failed to query high-risk nodes: {e}")
            return []
    
    async def _process_node_risk(self, node: Dict[str, Any]) -> None:
        """Process risk for a single node."""
        node_id = node["id"]
        current_score = node.get("risk_score", 50.0)
        
        # Update history
        if node_id not in self._risk_history:
            self._risk_history[node_id] = []
        self._risk_history[node_id].append(current_score)
        if len(self._risk_history[node_id]) > 100:
            self._risk_history[node_id] = self._risk_history[node_id][-100:]
        
        # Determine state
        new_state = self._determine_state(current_score)
        old_state = self._current_states.get(node_id, RiskState.NORMAL)
        
        # Determine trend
        trend = self._calculate_trend(node_id)
        
        # State change detected
        if new_state != old_state or new_state in (RiskState.CRITICAL, RiskState.EMERGENCY):
            previous_score = self._risk_history[node_id][-2] if len(self._risk_history[node_id]) > 1 else current_score
            
            event = await self._create_event(
                node_id=node_id,
                node_type=node.get("type", "unknown"),
                risk_score=current_score,
                previous_score=previous_score,
                risk_state=new_state,
                trend=trend,
                details={"state_change": f"{old_state.value} -> {new_state.value}"},
            )
            
            self._current_states[node_id] = new_state
            
            # Trigger responses
            await self._handle_event(event)
    
    def _determine_state(self, score: float) -> RiskState:
        """Determine risk state from score."""
        if score >= self.thresholds.emergency:
            return RiskState.EMERGENCY
        elif score >= self.thresholds.critical:
            return RiskState.CRITICAL
        elif score >= self.thresholds.high:
            return RiskState.HIGH
        elif score >= self.thresholds.elevated:
            return RiskState.ELEVATED
        else:
            return RiskState.NORMAL
    
    def _calculate_trend(self, node_id: str) -> str:
        """Calculate risk trend."""
        history = self._risk_history.get(node_id, [])
        if len(history) < 2:
            return "stable"
        
        recent = history[-5:] if len(history) >= 5 else history
        avg_change = (recent[-1] - recent[0]) / len(recent)
        
        if avg_change > self.config.trend_sensitivity:
            return "increasing"
        elif avg_change < -self.config.trend_sensitivity:
            return "decreasing"
        else:
            return "stable"
    
    async def _create_event(
        self,
        node_id: str,
        node_type: str,
        risk_score: float,
        previous_score: float,
        risk_state: RiskState,
        trend: str,
        details: Dict[str, Any]
    ) -> RiskEvent:
        """Create and store a risk event."""
        self._event_counter += 1
        event = RiskEvent(
            event_id=f"risk-{self._event_counter:08d}",
            timestamp=datetime.now(timezone.utc),
            node_id=node_id,
            node_type=node_type,
            risk_score=risk_score,
            previous_score=previous_score,
            risk_state=risk_state,
            trend=trend,
            details=details,
        )
        self._events.append(event)
        return event
    
    async def _handle_event(self, event: RiskEvent) -> None:
        """Handle a risk event with appropriate response."""
        # Call registered callbacks
        for callback in self._callbacks[event.risk_state]:
            try:
                await callback(event)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")
        
        # Determine actions based on policy
        actions = self._get_actions_for_state(event.risk_state)
        
        for action in actions:
            can_auto = self._can_auto_execute(event, action)
            
            if can_auto and self.response_engine:
                await self._execute_action(event, action)
            elif can_auto:
                # Log action that would be taken
                self.logger.info(
                    f"Would execute {action.value} for {event.node_id} "
                    f"(risk: {event.risk_score:.1f})"
                )
                event.actions_taken.append(f"{action.value} (simulated)")
    
    def _get_actions_for_state(self, state: RiskState) -> List[ActionType]:
        """Get actions for a risk state."""
        if state == RiskState.EMERGENCY:
            return [ActionType.ALERT, ActionType.ISOLATE, ActionType.ESCALATE]
        elif state == RiskState.CRITICAL:
            return [ActionType.ALERT, ActionType.RESTRICT, ActionType.AUDIT]
        elif state == RiskState.HIGH:
            return [ActionType.ALERT, ActionType.AUDIT]
        elif state == RiskState.ELEVATED:
            return [ActionType.REPORT]
        else:
            return []
    
    def _can_auto_execute(self, event: RiskEvent, action: ActionType) -> bool:
        """Check if action can be auto-executed."""
        if not self.config.auto_remediate:
            return False
        
        if event.risk_score > self.config.require_approval_above:
            return action == ActionType.ALERT  # Only alerts auto-execute
        
        if self._actions_this_hour >= self.config.max_auto_actions_per_hour:
            return False
        
        return True
    
    async def _execute_action(self, event: RiskEvent, action: ActionType) -> None:
        """Execute an autonomous action."""
        self._actions_this_hour += 1
        
        if self.response_engine:
            await self.response_engine.execute(
                action_type=action,
                target_id=event.node_id,
                event=event,
            )
        
        event.actions_taken.append(action.value)
        self.logger.info(f"Executed {action.value} for {event.node_id}")
    
    def register_callback(
        self,
        state: RiskState,
        callback: Callable[[RiskEvent], Any]
    ) -> None:
        """Register callback for a risk state."""
        self._callbacks[state].append(callback)
    
    def get_current_state(self, node_id: str) -> RiskState:
        """Get current state for a node."""
        return self._current_states.get(node_id, RiskState.NORMAL)
    
    def get_events(
        self,
        node_id: Optional[str] = None,
        state: Optional[RiskState] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[RiskEvent]:
        """Query risk events."""
        results = []
        for event in reversed(self._events):
            if node_id and event.node_id != node_id:
                continue
            if state and event.risk_state != state:
                continue
            if since and event.timestamp < since:
                continue
            results.append(event)
            if len(results) >= limit:
                break
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        state_counts = {}
        for state in self._current_states.values():
            state_counts[state.value] = state_counts.get(state.value, 0) + 1
        
        return {
            "monitoring_active": self._running,
            "monitored_nodes": len(self._current_states),
            "state_distribution": state_counts,
            "total_events": len(self._events),
            "actions_this_hour": self._actions_this_hour,
            "config": {
                "check_interval": self.config.check_interval_seconds,
                "auto_remediate": self.config.auto_remediate,
            },
        }
    
    async def trigger_manual_check(self, node_ids: List[str] = None) -> List[RiskEvent]:
        """Trigger manual risk check."""
        events = []
        # In production, would check specific nodes
        await self._check_all_risks()
        return self.get_events(limit=10)
