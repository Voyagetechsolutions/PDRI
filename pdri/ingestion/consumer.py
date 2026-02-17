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
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime, timezone

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import KafkaError

from pdri.config import settings
from shared.schemas.events import SecurityEvent


logger = logging.getLogger(__name__)


class _LRUSet:
    """LRU-evicting set for idempotency tracking."""

    def __init__(self, max_size: int = 100_000):
        self._max_size = max_size
        self._data: OrderedDict[str, None] = OrderedDict()

    def __contains__(self, key: str) -> bool:
        if key in self._data:
            self._data.move_to_end(key)
            return True
        return False

    def add(self, key: str) -> None:
        if key in self._data:
            self._data.move_to_end(key)
        else:
            self._data[key] = None
            if len(self._data) > self._max_size:
                self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


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
        bootstrap_servers: Optional[str] = None,
        dlq_topic: Optional[str] = None,
        max_retries: int = 3,
    ):
        """
        Initialize the event consumer.
        
        Args:
            topic: Kafka topic (defaults to config)
            group_id: Consumer group (defaults to config)
            bootstrap_servers: Kafka servers (defaults to config)
            dlq_topic: Dead letter queue topic (defaults to main topic + '.dlq')
            max_retries: Max retries before routing to DLQ
        """
        self.topic = topic or settings.kafka_security_events_topic
        self.group_id = group_id or settings.kafka_consumer_group
        self.bootstrap_servers = (
            bootstrap_servers or settings.kafka_bootstrap_servers
        )
        self.dlq_topic = dlq_topic or f"{self.topic}.dlq"
        self.max_retries = max_retries
        
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._dlq_producer: Optional[AIOKafkaProducer] = None
        self._handlers: list[Callable[[SecurityEvent], None]] = []
        self._running = False
        self._seen_ids = _LRUSet(max_size=100_000)
        self._stats = {
            "messages_consumed": 0,
            "messages_processed": 0,
            "messages_failed": 0,
            "messages_deduplicated": 0,
            "messages_dlq": 0,
            "last_message_at": None,
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
        
        # Start DLQ producer
        self._dlq_producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        
        await self._consumer.start()
        await self._dlq_producer.start()
        self._running = True
        logger.info("Kafka consumer started (DLQ enabled)")
    
    async def stop(self) -> None:
        """
        Stop the Kafka consumer gracefully.
        """
        logger.info("Stopping Kafka consumer")
        self._running = False
        
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None
        
        if self._dlq_producer:
            await self._dlq_producer.stop()
            self._dlq_producer = None
        
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
        Includes idempotency check and DLQ routing.
        """
        self._stats["messages_consumed"] += 1
        self._stats["last_message_at"] = datetime.now(timezone.utc)
        
        try:
            # Message value is already deserialized by _deserialize_message
            event_data = message.value
            
            if event_data is None:
                logger.warning(f"Received null message at offset {message.offset}")
                return
            
            # Create SecurityEvent from data
            event = SecurityEvent.from_kafka_message(event_data)
            
            # --- Idempotency check ---
            if event.event_id in self._seen_ids:
                self._stats["messages_deduplicated"] += 1
                logger.debug(f"Skipping duplicate event {event.event_id}")
                return
            self._seen_ids.add(event.event_id)
            
            logger.debug(
                f"Processing event {event.event_id} "
                f"type={event.event_type.value}"
            )
            
            # Route to all registered handlers with retry
            for handler in self._handlers:
                await self._invoke_handler_with_retry(handler, event)
            
            self._stats["messages_processed"] += 1
            
        except Exception as e:
            logger.error(
                f"Failed to process message at offset {message.offset}: {e}",
                exc_info=True
            )
            self._stats["messages_failed"] += 1
            await self._send_to_dlq(message, str(e))

    async def _invoke_handler_with_retry(
        self, handler: Callable, event: SecurityEvent
    ) -> None:
        """Invoke a handler with retry logic."""
        last_error: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
                return  # Success
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Handler {handler.__name__} attempt {attempt}/{self.max_retries} "
                    f"failed: {e}"
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * attempt)  # Backoff

        # All retries exhausted
        logger.error(
            f"Handler {handler.__name__} failed after {self.max_retries} retries"
        )
        await self._send_to_dlq_event(event, str(last_error))

    async def _send_to_dlq(self, message: Any, error: str) -> None:
        """Send a failed raw message to the dead letter queue."""
        if not self._dlq_producer:
            return
        try:
            dlq_payload = {
                "original_topic": self.topic,
                "original_offset": message.offset,
                "original_partition": message.partition,
                "error": error,
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "raw_value": message.value,
            }
            await self._dlq_producer.send_and_wait(self.dlq_topic, dlq_payload)
            self._stats["messages_dlq"] += 1
            logger.info(f"Sent failed message to DLQ: {self.dlq_topic}")
        except Exception as dlq_err:
            logger.error(f"Failed to send to DLQ: {dlq_err}")

    async def _send_to_dlq_event(
        self, event: SecurityEvent, error: str
    ) -> None:
        """Send a failed SecurityEvent to the dead letter queue."""
        if not self._dlq_producer:
            return
        try:
            dlq_payload = {
                "original_topic": self.topic,
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "error": error,
                "failed_at": datetime.now(timezone.utc).isoformat(),
            }
            await self._dlq_producer.send_and_wait(self.dlq_topic, dlq_payload)
            self._stats["messages_dlq"] += 1
        except Exception as dlq_err:
            logger.error(f"Failed to send event to DLQ: {dlq_err}")
    
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
