"""
Audit Trail
===========

Immutable audit logging for compliance.

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import json


class AuditEventType(Enum):
    """Types of audit events."""
    # Data events
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    DATA_EXPORT = "data_export"
    
    # Security events
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    # Administrative events
    CONFIG_CHANGE = "config_change"
    USER_MANAGEMENT = "user_management"
    POLICY_CHANGE = "policy_change"
    
    # Compliance events
    COMPLIANCE_CHECK = "compliance_check"
    RISK_ASSESSMENT = "risk_assessment"
    EVIDENCE_COLLECTION = "evidence_collection"
    
    # System events
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    BACKUP = "backup"
    RESTORE = "restore"


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """An immutable audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    actor: str
    action: str
    resource: str
    outcome: str  # success, failure, partial
    details: Dict[str, Any]
    severity: AuditSeverity = AuditSeverity.INFO
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    hash: str = field(default="", init=False)
    
    def __post_init__(self):
        """Calculate event hash for integrity."""
        self.hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of event content."""
        content = json.dumps({
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "details": self.details,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "details": self.details,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "hash": self.hash,
        }


class AuditTrail:
    """
    Immutable audit trail for compliance.
    
    Features:
    - Tamper-evident logging (hash chain)
    - Structured event capture
    - Query and export capabilities
    - Retention policy support
    
    Example:
        audit = AuditTrail()
        audit.log(
            event_type=AuditEventType.DATA_ACCESS,
            actor="user@example.com",
            action="read",
            resource="customer_data_store",
            outcome="success",
            details={"records": 100}
        )
    """
    
    def __init__(
        self,
        storage_backend: Optional[Any] = None,
        retention_days: int = 365
    ):
        """
        Initialize audit trail.
        
        Args:
            storage_backend: Optional persistent storage
            retention_days: Days to retain audit logs
        """
        self.storage_backend = storage_backend
        self.retention_days = retention_days
        
        self._events: List[AuditEvent] = []
        self._event_counter = 0
        self._last_hash = "0" * 64  # Genesis hash
    
    def log(
        self,
        event_type: AuditEventType,
        actor: str,
        action: str,
        resource: str,
        outcome: str,
        details: Dict[str, Any] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        source_ip: str = None,
        session_id: str = None,
        correlation_id: str = None
    ) -> AuditEvent:
        """
        Log an audit event.
        
        Args:
            event_type: Type of event
            actor: Who performed the action
            action: What action was performed
            resource: What resource was affected
            outcome: success, failure, partial
            details: Additional details
            severity: Event severity
            source_ip: Source IP address
            session_id: Session identifier
            correlation_id: For linking related events
        
        Returns:
            Created AuditEvent
        """
        self._event_counter += 1
        event_id = f"audit-{self._event_counter:010d}"
        
        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.utcnow(),
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details or {},
            severity=severity,
            source_ip=source_ip,
            session_id=session_id,
            correlation_id=correlation_id,
        )
        
        # Chain hash for tamper detection
        chain_content = f"{self._last_hash}{event.hash}"
        self._last_hash = hashlib.sha256(chain_content.encode()).hexdigest()
        
        self._events.append(event)
        
        # Persist if storage available
        if self.storage_backend:
            self._persist_event(event)
        
        return event
    
    def _persist_event(self, event: AuditEvent) -> None:
        """Persist event to storage backend."""
        if hasattr(self.storage_backend, 'write'):
            self.storage_backend.write(event.to_dict())
    
    def query(
        self,
        event_type: Optional[AuditEventType] = None,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[AuditSeverity] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """
        Query audit events.
        
        Args:
            event_type: Filter by event type
            actor: Filter by actor
            resource: Filter by resource
            start_time: Filter by start time
            end_time: Filter by end time
            severity: Filter by severity
            limit: Maximum results
        
        Returns:
            List of matching events
        """
        results = []
        
        for event in reversed(self._events):
            if event_type and event.event_type != event_type:
                continue
            if actor and event.actor != actor:
                continue
            if resource and event.resource != resource:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            if severity and event.severity != severity:
                continue
            
            results.append(event)
            if len(results) >= limit:
                break
        
        return results
    
    def verify_integrity(self) -> bool:
        """
        Verify audit trail integrity.
        
        Returns:
            True if chain is intact, False if tampered
        """
        current_hash = "0" * 64
        
        for event in self._events:
            # Verify event hash
            expected_hash = event._calculate_hash()
            if event.hash != expected_hash:
                return False
            
            # Update chain
            chain_content = f"{current_hash}{event.hash}"
            current_hash = hashlib.sha256(chain_content.encode()).hexdigest()
        
        return current_hash == self._last_hash
    
    def export(
        self,
        format: str = "json",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> str:
        """Export audit trail."""
        events = self.query(start_time=start_time, end_time=end_time, limit=10000)
        
        if format == "json":
            return json.dumps([e.to_dict() for e in events], indent=2)
        elif format == "csv":
            lines = ["event_id,event_type,timestamp,actor,action,resource,outcome"]
            for e in events:
                lines.append(f"{e.event_id},{e.event_type.value},{e.timestamp},{e.actor},{e.action},{e.resource},{e.outcome}")
            return "\n".join(lines)
        else:
            raise ValueError(f"Unknown format: {format}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit trail statistics."""
        if not self._events:
            return {"total_events": 0}
        
        event_types = {}
        actors = {}
        severities = {}
        
        for event in self._events:
            event_types[event.event_type.value] = event_types.get(event.event_type.value, 0) + 1
            actors[event.actor] = actors.get(event.actor, 0) + 1
            severities[event.severity.value] = severities.get(event.severity.value, 0) + 1
        
        return {
            "total_events": len(self._events),
            "event_types": event_types,
            "top_actors": dict(sorted(actors.items(), key=lambda x: x[1], reverse=True)[:10]),
            "severities": severities,
            "first_event": self._events[0].timestamp.isoformat(),
            "last_event": self._events[-1].timestamp.isoformat(),
            "integrity_verified": self.verify_integrity(),
        }
