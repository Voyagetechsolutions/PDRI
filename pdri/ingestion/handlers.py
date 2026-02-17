"""
PDRI Event Handlers
===================

Handler functions for processing security events.

Each handler is responsible for:
    - Interpreting the event type
    - Updating the risk graph
    - Triggering score recalculations

Author: PDRI Team
Version: 1.0.0
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from shared.schemas.events import (
    SecurityEvent,
    SecurityEventType,
    ExposureDirection,
)
from pdri.graph.engine import GraphEngine
from pdri.graph.models import (
    NodeType,
    EdgeType,
    GraphEdge,
    DataStoreNode,
    ServiceNode,
    AIToolNode,
    IdentityNode,
)
from pdri.scoring.engine import ScoringEngine


logger = logging.getLogger(__name__)


class EventHandlers:
    """
    Event handler implementations for security events.
    
    Provides handler methods for each event type that update
    the risk graph and trigger re-scoring.
    
    Usage:
        handlers = EventHandlers(graph_engine, scoring_engine)
        consumer.register_handler(handlers.handle_event)
    """
    
    def __init__(
        self,
        graph_engine: GraphEngine,
        scoring_engine: Optional[ScoringEngine] = None
    ):
        """
        Initialize handlers.
        
        Args:
            graph_engine: Connected GraphEngine instance
            scoring_engine: Optional ScoringEngine for auto-rescoring
        """
        self.graph = graph_engine
        self.scoring = scoring_engine
        
        # Handler dispatch table
        self._handlers = {
            SecurityEventType.AI_DATA_ACCESS: self._handle_ai_data_access,
            SecurityEventType.AI_PROMPT_SENSITIVE: self._handle_ai_prompt_sensitive,
            SecurityEventType.AI_API_INTEGRATION: self._handle_ai_integration,
            SecurityEventType.AI_AGENT_PRIV_ACCESS: self._handle_ai_priv_access,
            SecurityEventType.UNSANCTIONED_AI_TOOL: self._handle_unsanctioned_ai,
            SecurityEventType.SYSTEM_ACCESS: self._handle_system_access,
            SecurityEventType.DATA_MOVEMENT: self._handle_data_movement,
            SecurityEventType.DATA_EXPORT: self._handle_data_export,
        }
    
    async def handle_event(self, event: SecurityEvent) -> None:
        """
        Main event handler - routes to specific handlers.
        
        This method is registered with the Kafka consumer.
        
        Args:
            event: Validated SecurityEvent
        """
        logger.info(
            f"Handling event {event.event_id} type={event.event_type.value}"
        )
        
        handler = self._handlers.get(event.event_type)
        
        if handler:
            try:
                affected_entities = await handler(event)
                
                # Trigger re-scoring for affected entities
                if self.scoring and affected_entities:
                    await self._rescore_entities(affected_entities)
                    
            except Exception as e:
                logger.error(
                    f"Error handling event {event.event_id}: {e}",
                    exc_info=True
                )
        else:
            logger.warning(
                f"No handler for event type: {event.event_type.value}"
            )
    
    async def _handle_ai_data_access(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle AI_DATA_ACCESS events.
        
        Creates or updates connection between AI tool and data store.
        """
        affected = []
        
        # Ensure AI tool node exists
        ai_tool_id = event.identity_id or f"ai-unknown-{event.event_id[:8]}"
        ai_node = await self.graph.get_node(ai_tool_id)
        
        if ai_node is None:
            # Create the AI tool node
            new_node = AIToolNode(
                id=ai_tool_id,
                name=event.metadata.get("tool_name", "Unknown AI Tool"),
                vendor=event.metadata.get("vendor", "Unknown"),
                tool_name=event.metadata.get("tool_name", "Unknown"),
                is_sanctioned=event.metadata.get("sanctioned", False),
                access_level=event.privilege_level
            )
            await self.graph.create_node(new_node)
            affected.append(ai_tool_id)
        
        # Ensure data store node exists
        if event.target_entity_id:
            data_store = await self.graph.get_node(event.target_entity_id)
            
            if data_store is None:
                # Create placeholder data store
                new_ds = DataStoreNode(
                    id=event.target_entity_id,
                    name=event.metadata.get("target_name", event.target_entity_id),
                    store_type=event.metadata.get("store_type", "database")
                )
                await self.graph.create_node(new_ds)
            
            affected.append(event.target_entity_id)
            
            # Create access edge
            edge = GraphEdge(
                id=f"edge-{event.event_id}",
                edge_type=EdgeType.ACCESSES,
                source_id=ai_tool_id,
                target_id=event.target_entity_id,
                last_activity=event.timestamp,
                weight=self._calculate_edge_weight(event)
            )
            await self.graph.create_edge(edge)
        
        logger.info(
            f"Processed AI_DATA_ACCESS: {ai_tool_id} -> "
            f"{event.target_entity_id}"
        )
        
        return affected
    
    async def _handle_ai_prompt_sensitive(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle AI_PROMPT_SENSITIVE events.
        
        Increases sensitivity likelihood for involved entities.
        """
        affected = []
        
        # Update source system sensitivity
        if event.source_system_id:
            node = await self.graph.get_node(event.source_system_id)
            if node:
                # Increase sensitivity based on tags
                current = node.get("sensitivity_likelihood", 0.0)
                boost = 0.1 * len(event.sensitivity_tags)
                new_sensitivity = min(1.0, current + boost)
                
                await self.graph.update_node(
                    event.source_system_id,
                    {"sensitivity_likelihood": new_sensitivity}
                )
                affected.append(event.source_system_id)
        
        return affected
    
    async def _handle_ai_integration(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle AI_API_INTEGRATION events.
        
        Records new integration between a service and AI API.
        """
        affected = []
        
        # Create service node if needed
        service_id = event.source_system_id
        service = await self.graph.get_node(service_id)
        
        if service is None:
            new_service = ServiceNode(
                id=service_id,
                name=event.metadata.get("service_name", service_id),
                service_type="application"
            )
            await self.graph.create_node(new_service)
        
        affected.append(service_id)
        
        # Create AI tool node
        ai_tool_id = event.target_entity_id or f"ai-api-{event.event_id[:8]}"
        ai_node = await self.graph.get_node(ai_tool_id)
        
        if ai_node is None:
            new_ai = AIToolNode(
                id=ai_tool_id,
                name=event.metadata.get("api_name", ai_tool_id),
                vendor=event.metadata.get("vendor", "Unknown"),
                tool_name=event.metadata.get("api_name", "Unknown"),
                sends_data_external=True
            )
            await self.graph.create_node(new_ai)
        
        affected.append(ai_tool_id)
        
        # Create integration edge
        edge = GraphEdge(
            id=f"edge-{event.event_id}",
            edge_type=EdgeType.INTEGRATES_WITH,
            source_id=service_id,
            target_id=ai_tool_id,
            last_activity=event.timestamp
        )
        await self.graph.create_edge(edge)
        
        logger.info(
            f"Processed AI_API_INTEGRATION: {service_id} -> {ai_tool_id}"
        )
        
        return affected
    
    async def _handle_ai_priv_access(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle AI_AGENT_PRIV_ACCESS events.
        
        High-risk event - AI using elevated privileges.
        """
        affected = []
        
        # Update edge with privilege info
        if event.identity_id and event.target_entity_id:
            # This is high priority - update node metadata
            await self.graph.update_node(
                event.target_entity_id,
                {
                    "last_privileged_access": event.timestamp.isoformat(),
                    "last_privileged_accessor": event.identity_id
                }
            )
            affected.append(event.target_entity_id)
        
        logger.warning(
            f"HIGH RISK: AI privileged access detected - "
            f"{event.identity_id} on {event.target_entity_id}"
        )
        
        return affected
    
    async def _handle_unsanctioned_ai(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle UNSANCTIONED_AI_TOOL events.
        
        Unknown AI tool detected - create with high risk flags.
        """
        affected = []
        
        # Create unsanctioned AI tool node
        ai_tool_id = event.identity_id or f"unsanctioned-{event.event_id[:8]}"
        
        new_ai = AIToolNode(
            id=ai_tool_id,
            name=event.metadata.get("tool_name", "Unknown AI Tool"),
            vendor=event.metadata.get("vendor", "Unknown"),
            tool_name=event.metadata.get("tool_name", "Unknown"),
            is_sanctioned=False,
            sends_data_external=True,
            exposure_score=0.9,  # Start with high exposure
            tags=["unsanctioned", "high_risk"]
        )
        await self.graph.create_node(new_ai)
        affected.append(ai_tool_id)
        
        logger.warning(
            f"UNSANCTIONED AI TOOL detected: {ai_tool_id}"
        )
        
        return affected
    
    async def _handle_system_access(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle general SYSTEM_ACCESS events.
        
        Updates access patterns in the graph.
        """
        affected = []
        
        # Ensure identity exists
        if event.identity_id:
            identity = await self.graph.get_node(event.identity_id)
            if identity is None:
                new_identity = IdentityNode(
                    id=event.identity_id,
                    name=event.metadata.get("identity_name", event.identity_id),
                    identity_type=event.metadata.get("identity_type", "user"),
                    privilege_level=event.privilege_level
                )
                await self.graph.create_node(new_identity)
            affected.append(event.identity_id)
        
        # Update or create access edge
        if event.identity_id and event.target_entity_id:
            edge = GraphEdge(
                id=f"access-{event.identity_id}-{event.target_entity_id}",
                edge_type=EdgeType.ACCESSES,
                source_id=event.identity_id,
                target_id=event.target_entity_id,
                last_activity=event.timestamp
            )
            await self.graph.create_edge(edge)
            
            if event.target_entity_id not in affected:
                affected.append(event.target_entity_id)
        
        return affected
    
    async def _handle_data_movement(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle DATA_MOVEMENT events.
        
        Records data flow between entities.
        """
        affected = []
        
        source = event.source_system_id
        target = event.target_entity_id
        
        if source and target:
            edge = GraphEdge(
                id=f"dataflow-{event.event_id}",
                edge_type=EdgeType.MOVES_DATA_TO,
                source_id=source,
                target_id=target,
                last_activity=event.timestamp,
                data_volume_bytes=event.data_volume_estimate
            )
            await self.graph.create_edge(edge)
            
            affected.extend([source, target])
            
            logger.info(
                f"Data movement recorded: {source} -> {target} "
                f"({event.data_volume_estimate or 'unknown'} bytes)"
            )
        
        return affected
    
    async def _handle_data_export(
        self, 
        event: SecurityEvent
    ) -> list[str]:
        """
        Handle DATA_EXPORT events.
        
        Creates external exposure edge.
        """
        affected = []
        
        source = event.source_system_id
        
        if source:
            # Mark as exposing data externally
            edge = GraphEdge(
                id=f"export-{event.event_id}",
                edge_type=EdgeType.EXPOSES,
                source_id=source,
                target_id=event.target_entity_id or "external:unknown",
                last_activity=event.timestamp,
                data_volume_bytes=event.data_volume_estimate
            )
            await self.graph.create_edge(edge)
            
            affected.append(source)
            
            logger.warning(
                f"Data export detected from {source} "
                f"({event.exposure_direction.value})"
            )
        
        return affected
    
    def _calculate_edge_weight(self, event: SecurityEvent) -> float:
        """
        Calculate edge weight based on event attributes.
        
        Higher weight = more significant relationship.
        """
        weight = 1.0
        
        # Adjust for privilege level
        if event.privilege_level in ["admin", "super_admin"]:
            weight += 0.5
        
        # Adjust for sensitivity
        weight += len(event.sensitivity_tags) * 0.1
        
        # Adjust for volume
        if event.data_volume_estimate:
            if event.data_volume_estimate > 10_000_000:
                weight += 0.3
            elif event.data_volume_estimate > 1_000_000:
                weight += 0.15
        
        return min(2.0, weight)
    
    async def _rescore_entities(self, entity_ids: list[str]) -> None:
        """
        Trigger re-scoring for affected entities.
        """
        if not self.scoring:
            return
        
        for entity_id in entity_ids:
            try:
                await self.scoring.score_entity(entity_id)
            except Exception as e:
                logger.error(f"Failed to rescore {entity_id}: {e}")
