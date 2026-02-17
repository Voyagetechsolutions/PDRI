"""
PDRI Event Consumer
===================

Kafka consumer for security events.

Consumes events from the security-events topic and routes
them to appropriate handlers for processing.

Usage:
    consumer = EventConsumer(graph_engine, scoring_engine)
    await consumer.start()
    # ... run until shutdown
    await consumer.stop()

Author: PDRI Team
Version: 1.0.0
"""

import json
import logging
import asyncio
from typing import Any, Callable, Dict, Optional
from datetime import datetime

from aiokafka import AIOKafkaConsumer
from aiokafka.errors import KafkaError

from pdri.config import settings
from shared.schemas.events import SecurityEvent


logger = logging.getLogger(__name__)


class EventConsumer:
    """
    Async Kafka consumer for security events.
    
    Consumes events from the configured Kafka topic,
    validates against the SecurityEvent schema, and
    routes to registered handlers.
    
    Attributes:
        topic: Kafka topic to consume from
        group_id: Consumer group identifier
        
    Example:
        consumer = EventConsumer()
        consumer.register_handler(handler_function)
        
        try:
            await consumer.start()
            await consumer.consume_forever()
        finally:
            await consumer.stop()
    """
    
    def __init__(
        self,
        topic: Optional[str] = None,
        group_id: Optional[str] = None,
        bootstrap_servers: Optional[str] = None
    ):
        """
        Initialize the event consumer.
        
        Args:
            topic: Kafka topic (defaults to config)
            group_id: Consumer group (defaults to config)
            bootstrap_servers: Kafka servers (defaults to config)
        """
        self.topic = topic or settings.kafka_security_events_topic
        self.group_id = group_id or settings.kafka_consumer_group
        self.bootstrap_servers = (
            bootstrap_servers or settings.kafka_bootstrap_servers
        )
        
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._handlers: list[Callable[[SecurityEvent], None]] = []
        self._running = False
        self._stats = {
            "messages_consumed": 0,
            "messages_processed": 0,
            "messages_failed": 0,
            "last_message_at": None
        }
    
    def register_handler(
        self, 
        handler: Callable[[SecurityEvent], None]
    ) -> None:
        """
        Register a handler for processed events.
        
        Args:
            handler: Async function that takes a SecurityEvent
        """
        self._handlers.append(handler)
        logger.info(f"Registered event handler: {handler.__name__}")
    
    async def start(self) -> None:
        """
        Start the Kafka consumer.
        
        Creates connection and subscribes to topic.
        """
        logger.info(
            f"Starting Kafka consumer for topic '{self.topic}' "
            f"with group '{self.group_id}'"
        )
        
        self._consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            value_deserializer=self._deserialize_message,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            auto_commit_interval_ms=5000
        )
        
        await self._consumer.start()
        self._running = True
        logger.info("Kafka consumer started")
    
    async def stop(self) -> None:
        """
        Stop the Kafka consumer gracefully.
        """
        logger.info("Stopping Kafka consumer")
        self._running = False
        
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None
        
        logger.info("Kafka consumer stopped")
    
    async def consume_forever(self) -> None:
        """
        Consume messages indefinitely until stopped.
        
        Call stop() from another task to terminate.
        """
        if not self._consumer:
            raise RuntimeError("Consumer not started. Call start() first.")
        
        logger.info("Starting message consumption loop")
        
        try:
            async for message in self._consumer:
                if not self._running:
                    break
                
                await self._process_message(message)
                
        except KafkaError as e:
            logger.error(f"Kafka error during consumption: {e}")
            raise
    
    async def consume_batch(
        self, 
        max_messages: int = 100,
        timeout_ms: int = 1000
    ) -> int:
        """
        Consume a batch of messages.
        
        Useful for controlled processing or testing.
        
        Args:
            max_messages: Maximum messages to consume
            timeout_ms: Timeout for batch collection
            
        Returns:
            Number of messages processed
        """
        if not self._consumer:
            raise RuntimeError("Consumer not started")
        
        records = await self._consumer.getmany(
            timeout_ms=timeout_ms,
            max_records=max_messages
        )
        
        processed = 0
        for tp, messages in records.items():
            for message in messages:
                await self._process_message(message)
                processed += 1
        
        return processed
    
    async def _process_message(self, message: Any) -> None:
        """
        Process a single Kafka message.
        
        Validates, transforms, and routes to handlers.
        """
        self._stats["messages_consumed"] += 1
        self._stats["last_message_at"] = datetime.utcnow()
        
        try:
            # Message value is already deserialized by _deserialize_message
            event_data = message.value
            
            if event_data is None:
                logger.warning(f"Received null message at offset {message.offset}")
                return
            
            # Create SecurityEvent from data
            event = SecurityEvent.from_kafka_message(event_data)
            
            logger.debug(
                f"Processing event {event.event_id} "
                f"type={event.event_type.value}"
            )
            
            # Route to all registered handlers
            for handler in self._handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    logger.error(
                        f"Handler {handler.__name__} failed: {e}",
                        exc_info=True
                    )
            
            self._stats["messages_processed"] += 1
            
        except Exception as e:
            logger.error(
                f"Failed to process message at offset {message.offset}: {e}",
                exc_info=True
            )
            self._stats["messages_failed"] += 1
    
    def _deserialize_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Deserialize Kafka message from bytes.
        
        Args:
            data: Raw message bytes
            
        Returns:
            Parsed JSON dictionary or None
        """
        if data is None:
            return None
        
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Failed to deserialize message: {e}")
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get consumption statistics.
        
        Returns:
            Dictionary with consumption metrics
        """
        return {
            **self._stats,
            "running": self._running,
            "handler_count": len(self._handlers)
        }
