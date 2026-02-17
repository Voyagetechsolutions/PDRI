"""
Response Engine
===============

Automated response execution for risk events.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import asyncio
import logging


class ResponseStatus(Enum):
    """Status of a response action."""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLBACK = "rollback"


class ResponsePriority(Enum):
    """Priority levels for responses."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


@dataclass
class ResponseAction:
    """A response action to execute."""
    action_id: str
    action_type: str  # From ActionType
    target_id: str
    target_type: str
    priority: ResponsePriority
    status: ResponseStatus
    created_at: datetime
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    requires_approval: bool = False
    approved_by: Optional[str] = None
    rollback_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "priority": self.priority.name,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error,
            "requires_approval": self.requires_approval,
            "approved_by": self.approved_by,
        }


@dataclass
class ResponsePlaybook:
    """A playbook of response actions."""
    playbook_id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    actions: List[Dict[str, Any]]
    enabled: bool = True


class ResponseEngine:
    """
    Automated response execution engine.
    
    Features:
    - Action execution with rollback
    - Approval workflows
    - Priority queuing
    - Playbook support
    - Audit integration
    
    Example:
        engine = ResponseEngine()
        await engine.execute(
            action_type="restrict",
            target_id="node-123",
            event=risk_event
        )
    """
    
    def __init__(
        self,
        graph_engine: Any = None,
        audit_trail: Any = None,
        notification_handler: Callable = None,
        aegis_client: Any = None,
        dmitry_client: Any = None,
    ):
        """
        Initialize response engine.
        
        Args:
            graph_engine: Graph database for actions
            audit_trail: Audit trail for logging
            notification_handler: Handler for notifications
            aegis_client: AegisClient instance for incident reporting
            dmitry_client: DmitryBackendClient for NLP threat analysis
        """
        self.graph_engine = graph_engine
        self.audit_trail = audit_trail
        self.notification_handler = notification_handler
        self.aegis_client = aegis_client
        self.dmitry_client = dmitry_client
        
        self._action_counter = 0
        self._actions: Dict[str, ResponseAction] = {}
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._handlers: Dict[str, Callable] = {}
        self._playbooks: Dict[str, ResponsePlaybook] = {}
        
        self.logger = logging.getLogger("pdri.response")
        
        # Register default handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self) -> None:
        """Register default action handlers."""
        self._handlers = {
            "alert": self._handle_alert,
            "restrict": self._handle_restrict,
            "isolate": self._handle_isolate,
            "escalate": self._handle_escalate,
            "audit": self._handle_audit,
            "remediate": self._handle_remediate,
            "report": self._handle_report,
        }
    
    async def execute(
        self,
        action_type: Any,
        target_id: str,
        event: Any = None,
        priority: ResponsePriority = ResponsePriority.MEDIUM,
        requires_approval: bool = False,
        metadata: Dict[str, Any] = None
    ) -> ResponseAction:
        """
        Execute a response action.
        
        Args:
            action_type: Type of action (from ActionType enum or string)
            target_id: Target entity ID
            event: Triggering risk event
            priority: Action priority
            requires_approval: Whether approval is needed
            metadata: Additional action metadata
        
        Returns:
            ResponseAction with result
        """
        action_type_str = action_type.value if hasattr(action_type, 'value') else str(action_type)
        
        self._action_counter += 1
        action_id = f"action-{self._action_counter:08d}"
        
        action = ResponseAction(
            action_id=action_id,
            action_type=action_type_str,
            target_id=target_id,
            target_type=event.node_type if event else "unknown",
            priority=priority,
            status=ResponseStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            requires_approval=requires_approval,
            metadata=metadata or {},
        )
        
        self._actions[action_id] = action
        
        if requires_approval:
            # Queue for approval
            self.logger.info(f"Action {action_id} pending approval")
            if self.notification_handler:
                await self.notification_handler(action, "pending_approval")
            return action
        
        # Execute immediately
        return await self._execute_action(action)
    
    async def _execute_action(self, action: ResponseAction) -> ResponseAction:
        """Execute an action."""
        action.status = ResponseStatus.EXECUTING
        action.executed_at = datetime.now(timezone.utc)
        
        handler = self._handlers.get(action.action_type)
        if not handler:
            action.status = ResponseStatus.FAILED
            action.error = f"No handler for action type: {action.action_type}"
            return action
        
        try:
            result = await handler(action)
            action.status = ResponseStatus.COMPLETED
            action.result = result
            action.completed_at = datetime.now(timezone.utc)
            
            # Log to audit trail
            if self.audit_trail:
                from ..compliance.audit.audit_trail import AuditEventType
                self.audit_trail.log(
                    event_type=AuditEventType.CONFIG_CHANGE,
                    actor="pdri-response-engine",
                    action=action.action_type,
                    resource=action.target_id,
                    outcome="success",
                    details={"action_id": action.action_id, "result": result},
                )
            
            # Report to external integrations (fire-and-forget)
            await asyncio.gather(
                self._report_to_aegis(action),
                self._report_to_dmitry(action),
                return_exceptions=True,
            )
            
            self.logger.info(f"Action {action.action_id} completed successfully")
            
        except Exception as e:
            action.status = ResponseStatus.FAILED
            action.error = str(e)
            action.completed_at = datetime.now(timezone.utc)
            self.logger.error(f"Action {action.action_id} failed: {e}")
        
        return action
    
    # Default action handlers
    
    async def _handle_alert(self, action: ResponseAction) -> Dict[str, Any]:
        """Handle alert action."""
        if self.notification_handler:
            await self.notification_handler(action, "alert")
        
        return {
            "alerted": True,
            "target": action.target_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    async def _handle_restrict(self, action: ResponseAction) -> Dict[str, Any]:
        """Handle access restriction action."""
        # In production, would modify access controls
        return {
            "restricted": True,
            "target": action.target_id,
            "restrictions_applied": ["read_only", "no_external_access"],
            "rollback_available": True,
        }
    
    async def _handle_isolate(self, action: ResponseAction) -> Dict[str, Any]:
        """Handle network isolation action."""
        # In production, would isolate network segment
        return {
            "isolated": True,
            "target": action.target_id,
            "isolation_type": "network_segment",
            "allowed_connections": ["admin_only"],
        }
    
    async def _handle_escalate(self, action: ResponseAction) -> Dict[str, Any]:
        """Handle escalation action."""
        escalation_targets = ["security-team", "on-call-engineer"]
        
        if self.notification_handler:
            for target in escalation_targets:
                await self.notification_handler(action, f"escalation_{target}")
        
        return {
            "escalated": True,
            "escalation_targets": escalation_targets,
            "ticket_created": "INC-12345",
        }
    
    async def _handle_audit(self, action: ResponseAction) -> Dict[str, Any]:
        """Handle audit action."""
        return {
            "audit_triggered": True,
            "target": action.target_id,
            "audit_type": "security_review",
            "audit_id": f"audit-{action.action_id}",
        }
    
    async def _handle_remediate(self, action: ResponseAction) -> Dict[str, Any]:
        """Handle remediation action."""
        # In production, would execute remediation playbook
        return {
            "remediated": True,
            "target": action.target_id,
            "steps_executed": ["backup", "patch", "verify"],
            "verification_passed": True,
        }
    
    async def _handle_report(self, action: ResponseAction) -> Dict[str, Any]:
        """Handle report generation action."""
        return {
            "report_generated": True,
            "target": action.target_id,
            "report_type": "risk_summary",
            "report_id": f"rpt-{action.action_id}",
        }
    
    async def approve_action(
        self,
        action_id: str,
        approved_by: str
    ) -> ResponseAction:
        """Approve a pending action."""
        action = self._actions.get(action_id)
        if not action:
            raise ValueError(f"Action {action_id} not found")
        
        if action.status != ResponseStatus.PENDING:
            raise ValueError(f"Action {action_id} not pending approval")
        
        action.status = ResponseStatus.APPROVED
        action.approved_by = approved_by
        
        # Execute the action
        return await self._execute_action(action)
    
    async def reject_action(
        self,
        action_id: str,
        rejected_by: str,
        reason: str
    ) -> ResponseAction:
        """Reject a pending action."""
        action = self._actions.get(action_id)
        if not action:
            raise ValueError(f"Action {action_id} not found")
        
        action.status = ResponseStatus.CANCELLED
        action.error = f"Rejected by {rejected_by}: {reason}"
        return action
    
    async def rollback_action(self, action_id: str) -> ResponseAction:
        """Rollback a completed action."""
        action = self._actions.get(action_id)
        if not action:
            raise ValueError(f"Action {action_id} not found")
        
        if action.status != ResponseStatus.COMPLETED:
            raise ValueError(f"Cannot rollback action in state {action.status}")
        
        action.status = ResponseStatus.ROLLBACK
        self.logger.info(f"Action {action_id} rolled back")
        
        # In production, would execute rollback logic
        return action
    
    def register_handler(
        self,
        action_type: str,
        handler: Callable[[ResponseAction], Dict[str, Any]]
    ) -> None:
        """Register a custom action handler."""
        self._handlers[action_type] = handler
    
    def add_playbook(self, playbook: ResponsePlaybook) -> None:
        """Add a response playbook."""
        self._playbooks[playbook.playbook_id] = playbook
    
    async def execute_playbook(
        self,
        playbook_id: str,
        target_id: str,
        event: Any = None
    ) -> List[ResponseAction]:
        """Execute a response playbook."""
        playbook = self._playbooks.get(playbook_id)
        if not playbook or not playbook.enabled:
            raise ValueError(f"Playbook {playbook_id} not found or disabled")
        
        results = []
        for action_def in playbook.actions:
            action = await self.execute(
                action_type=action_def["type"],
                target_id=target_id,
                event=event,
                priority=ResponsePriority[action_def.get("priority", "MEDIUM")],
                requires_approval=action_def.get("requires_approval", False),
            )
            results.append(action)
        
        return results
    
    def get_action(self, action_id: str) -> Optional[ResponseAction]:
        """Get action by ID."""
        return self._actions.get(action_id)
    
    def get_pending_approvals(self) -> List[ResponseAction]:
        """Get actions pending approval."""
        return [
            a for a in self._actions.values()
            if a.status == ResponseStatus.PENDING and a.requires_approval
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get response engine statistics."""
        status_counts = {}
        type_counts = {}
        
        for action in self._actions.values():
            status_counts[action.status.value] = status_counts.get(action.status.value, 0) + 1
            type_counts[action.action_type] = type_counts.get(action.action_type, 0) + 1
        
        return {
            "total_actions": len(self._actions),
            "status_distribution": status_counts,
            "type_distribution": type_counts,
            "pending_approvals": len(self.get_pending_approvals()),
            "registered_handlers": list(self._handlers.keys()),
            "playbook_count": len(self._playbooks),
        }
    
    async def _report_to_aegis(self, action: ResponseAction) -> None:
        """
        Report a completed response action to AegisAI as an incident.
        
        Silently skips if no aegis_client is configured or if the report
        fails (does not block the response pipeline).
        """
        if not self.aegis_client:
            return
        
        try:
            from pdri.integrations.aegis_transformer import build_aegis_incident_payload
            
            incident = build_aegis_incident_payload(
                entity_id=action.target_id,
                action_type=action.action_type,
                severity=action.priority.name.lower(),
                description=(
                    f"PDRI automated response: {action.action_type} on "
                    f"{action.target_type} '{action.target_id}'"
                ),
                risk_score=action.metadata.get("risk_score"),
                recommendations=action.metadata.get("recommendations"),
                metadata={
                    "action_id": action.action_id,
                    "result": action.result,
                },
            )
            
            result = await self.aegis_client.report_incident(incident)
            self.logger.info(
                f"Reported action {action.action_id} to AegisAI — "
                f"ticket: {result.get('ticket_id', 'n/a')}"
            )
        except Exception as e:
            # Never let Aegis reporting failure block the response pipeline
            self.logger.warning(
                f"Failed to report action {action.action_id} to AegisAI: {e}"
            )

    async def _report_to_dmitry(self, action: ResponseAction) -> None:
        """
        Send a completed action to Dmitry for NLP threat analysis.

        Dmitry enriches the action with natural language context and
        stores it in its action logs. Silently skips if no dmitry_client
        is configured or if the call fails.
        """
        if not self.dmitry_client:
            return

        try:
            description = (
                f"PDRI Response Engine executed '{action.action_type}' "
                f"on {action.target_type} '{action.target_id}'. "
            )
            if action.result:
                description += f"Result: {action.result}. "
            description += (
                f"Priority: {action.priority.name}. "
                "Analyze the threat and recommend follow-up actions."
            )

            result = await self.dmitry_client.analyze_threat(description)
            self.logger.info(
                f"Reported action {action.action_id} to Dmitry — "
                f"intent: {result.get('intent', 'n/a')}"
            )
        except Exception as e:
            self.logger.warning(
                f"Failed to report action {action.action_id} to Dmitry: {e}"
            )
