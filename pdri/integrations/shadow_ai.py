"""
Shadow AI Integration - Event Producer
======================================

Stub implementation for Shadow AI event production.

In the full platform, Shadow AI detects AI tool usage and
produces security events to the Kafka bus for PDRI consumption.

This stub provides:
    - MockShadowAIProducer for testing
    - Event generation utilities
    - Kafka producer integration

Author: PDRI Team
Version: 1.0.0
"""

import json
import logging
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaError

from pdri.config import settings
from shared.schemas.events import (
    SecurityEvent,
    SecurityEventType,
    SensitivityTag,
    ExposureDirection,
)


logger = logging.getLogger(__name__)


class ShadowAIProducer:
    """
    Kafka producer for Shadow AI events.
    
    Produces security events to the Kafka topic for PDRI consumption.
    This is the integration point where Shadow AI sends detected
    AI usage events.
    
    Usage:
        async with ShadowAIProducer() as producer:
            await producer.send_ai_data_access(
                ai_tool_id="chatgpt-001",
                target_id="customer-db",
                identity_id="user-123"
            )
    """
    
    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topic: Optional[str] = None
    ):
        """
        Initialize the Shadow AI producer.
        
        Args:
            bootstrap_servers: Kafka servers (defaults to config)
            topic: Target topic (defaults to config)
        """
        self.bootstrap_servers = (
            bootstrap_servers or settings.kafka_bootstrap_servers
        )
        self.topic = topic or settings.kafka_security_events_topic
        self._producer: Optional[AIOKafkaProducer] = None
    
    async def start(self) -> None:
        """Start the Kafka producer."""
        logger.info(f"Starting Shadow AI producer for topic '{self.topic}'")
        
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8")
        )
        await self._producer.start()
        
        logger.info("Shadow AI producer started")
    
    async def stop(self) -> None:
        """Stop the Kafka producer."""
        if self._producer:
            await self._producer.stop()
            self._producer = None
            logger.info("Shadow AI producer stopped")
    
    async def __aenter__(self) -> "ShadowAIProducer":
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.stop()
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """
        Send a security event to Kafka.
        
        Args:
            event: SecurityEvent to send
            
        Returns:
            True if sent successfully
        """
        if not self._producer:
            raise RuntimeError("Producer not started")
        
        try:
            message = event.to_kafka_message()
            await self._producer.send_and_wait(self.topic, message)
            
            logger.debug(
                f"Sent event {event.event_id} ({event.event_type.value})"
            )
            return True
            
        except KafkaError as e:
            logger.error(f"Failed to send event: {e}")
            return False
    
    async def send_ai_data_access(
        self,
        ai_tool_id: str,
        target_id: str,
        identity_id: Optional[str] = None,
        sensitivity_tags: Optional[List[str]] = None,
        data_volume: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """
        Send an AI data access event.
        
        Call when an AI tool accesses a data store.
        
        Args:
            ai_tool_id: ID of the AI tool
            target_id: ID of the data store accessed
            identity_id: Optional user/service identity
            sensitivity_tags: Optional sensitivity indicators
            data_volume: Optional data volume estimate
            metadata: Additional event metadata
            
        Returns:
            The created SecurityEvent
        """
        tags = [SensitivityTag(t) for t in (sensitivity_tags or [])]
        
        event = SecurityEvent(
            event_type=SecurityEventType.AI_DATA_ACCESS,
            source_system_id="shadow-ai",
            target_entity_id=target_id,
            identity_id=ai_tool_id,
            sensitivity_tags=tags,
            exposure_direction=ExposureDirection.INTERNAL_TO_AI,
            data_volume_estimate=data_volume,
            privilege_level="read",
            metadata={
                **(metadata or {}),
                "ai_tool_id": ai_tool_id,
                "detected_by": "shadow-ai"
            }
        )
        
        await self.send_event(event)
        return event
    
    async def send_unsanctioned_ai_detection(
        self,
        tool_name: str,
        vendor: Optional[str] = None,
        user_identity: Optional[str] = None,
        data_accessed: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """
        Send an unsanctioned AI tool detection event.
        
        Call when an unapproved AI tool is detected.
        
        Args:
            tool_name: Name of the unsanctioned tool
            vendor: Tool vendor if known
            user_identity: User who used the tool
            data_accessed: Data that was accessed
            metadata: Additional event metadata
            
        Returns:
            The created SecurityEvent
        """
        event = SecurityEvent(
            event_type=SecurityEventType.UNSANCTIONED_AI_TOOL,
            source_system_id="shadow-ai",
            target_entity_id=data_accessed,
            identity_id=user_identity,
            sensitivity_tags=[SensitivityTag.UNKNOWN],
            exposure_direction=ExposureDirection.INTERNAL_TO_AI,
            privilege_level="unknown",
            metadata={
                **(metadata or {}),
                "tool_name": tool_name,
                "vendor": vendor or "Unknown",
                "sanctioned": False,
                "detection_source": "shadow-ai"
            }
        )
        
        await self.send_event(event)
        return event
    
    async def send_ai_prompt_sensitive(
        self,
        ai_tool_id: str,
        source_service: str,
        sensitivity_tags: List[str],
        data_volume: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """
        Send alert for sensitive data in AI prompt.
        
        Call when sensitive data is detected in an AI prompt/request.
        
        Args:
            ai_tool_id: AI tool receiving the prompt
            source_service: Service sending the prompt
            sensitivity_tags: Detected sensitivity types
            data_volume: Estimated data size
            metadata: Additional metadata
            
        Returns:
            The created SecurityEvent
        """
        tags = [SensitivityTag(t) for t in sensitivity_tags]
        
        event = SecurityEvent(
            event_type=SecurityEventType.AI_PROMPT_SENSITIVE,
            source_system_id=source_service,
            target_entity_id=ai_tool_id,
            identity_id=ai_tool_id,
            sensitivity_tags=tags,
            exposure_direction=ExposureDirection.INTERNAL_TO_AI,
            data_volume_estimate=data_volume,
            privilege_level="read",
            metadata={
                **(metadata or {}),
                "detection_type": "prompt_scan",
                "ai_tool_id": ai_tool_id
            }
        )
        
        await self.send_event(event)
        return event


class MockShadowAIProducer(ShadowAIProducer):
    """
    Mock producer for testing without Kafka.
    
    Stores events in memory instead of sending to Kafka.
    """
    
    def __init__(self):
        super().__init__()
        self.events: List[SecurityEvent] = []
    
    async def start(self) -> None:
        """Mock start - no-op."""
        logger.info("Mock Shadow AI producer started")
    
    async def stop(self) -> None:
        """Mock stop - no-op."""
        logger.info("Mock Shadow AI producer stopped")
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Store event in memory."""
        self.events.append(event)
        logger.debug(f"Mock stored event {event.event_id}")
        return True
    
    def get_events(self) -> List[SecurityEvent]:
        """Get all stored events."""
        return self.events
    
    def clear_events(self) -> None:
        """Clear stored events."""
        self.events.clear()
