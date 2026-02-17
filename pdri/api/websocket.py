"""
WebSocket Real-Time Risk Events
================================

FastAPI WebSocket endpoint for streaming risk score changes
and security events to connected clients.

Features:
    - Room/channel-based subscriptions
    - JWT auth on connect (query param)
    - Heartbeat ping/pong
    - Broadcast and targeted messaging

Author: PDRI Team
Version: 1.0.0
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from starlette.websockets import WebSocketState

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# Connection Manager
# =============================================================================

class WebSocketManager:
    """
    Manages active WebSocket connections with room support.
    
    Rooms:
        - "risk_events" — all risk score changes
        - "security_events" — ingested security events
        - "simulations" — simulation completions
        - "alerts" — high-risk alerts only
        - "all" — everything
    """
    
    VALID_ROOMS = {"risk_events", "security_events", "simulations", "alerts", "all"}
    HEARTBEAT_INTERVAL = 30  # seconds
    
    def __init__(self):
        self._connections: Dict[str, Set[WebSocket]] = {
            room: set() for room in self.VALID_ROOMS
        }
        self._user_map: Dict[WebSocket, Dict[str, Any]] = {}
        self._heartbeat_tasks: Dict[WebSocket, asyncio.Task] = {}
    
    @property
    def total_connections(self) -> int:
        """Total unique connected clients."""
        all_ws = set()
        for conns in self._connections.values():
            all_ws.update(conns)
        return len(all_ws)
    
    async def connect(
        self,
        websocket: WebSocket,
        rooms: List[str],
        user_info: Optional[Dict[str, Any]] = None,
    ):
        """
        Accept and register a WebSocket connection.
        
        Args:
            websocket: WebSocket connection
            rooms: Rooms to subscribe to
            user_info: Optional authenticated user info
        """
        await websocket.accept()
        
        for room in rooms:
            if room in self.VALID_ROOMS:
                self._connections[room].add(websocket)
        
        self._user_map[websocket] = user_info or {}
        
        # Start heartbeat
        task = asyncio.create_task(self._heartbeat(websocket))
        self._heartbeat_tasks[websocket] = task
        
        logger.info(
            f"WebSocket connected: rooms={rooms}, "
            f"user={user_info.get('sub', 'anonymous') if user_info else 'anonymous'}, "
            f"total={self.total_connections}"
        )
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "rooms": rooms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket from all rooms."""
        for room_conns in self._connections.values():
            room_conns.discard(websocket)
        
        self._user_map.pop(websocket, None)
        
        task = self._heartbeat_tasks.pop(websocket, None)
        if task:
            task.cancel()
        
        logger.info(f"WebSocket disconnected, total={self.total_connections}")
    
    async def broadcast(
        self,
        room: str,
        message: Dict[str, Any],
    ):
        """
        Send message to all connections in a room.
        
        Also sends to "all" room subscribers.
        
        Args:
            room: Target room
            message: Message payload
        """
        message["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        targets: Set[WebSocket] = set()
        targets.update(self._connections.get(room, set()))
        targets.update(self._connections.get("all", set()))
        
        disconnected = []
        for ws in targets:
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_json(message)
            except Exception:
                disconnected.append(ws)
        
        for ws in disconnected:
            await self.disconnect(ws)
    
    async def send_to_user(
        self,
        user_id: str,
        message: Dict[str, Any],
    ):
        """Send message to a specific user by ID."""
        message["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        for ws, info in self._user_map.items():
            if info.get("sub") == user_id:
                try:
                    if ws.client_state == WebSocketState.CONNECTED:
                        await ws.send_json(message)
                except Exception:
                    await self.disconnect(ws)
    
    async def _heartbeat(self, websocket: WebSocket):
        """Send periodic pings to keep connection alive."""
        try:
            while True:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json({
                        "type": "ping",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
        except asyncio.CancelledError:
            pass
        except Exception:
            pass


# Global manager instance
ws_manager = WebSocketManager()


# =============================================================================
# Helper: Broadcast Events (used by other modules)
# =============================================================================

async def broadcast_score_update(
    entity_id: str,
    old_score: float,
    new_score: float,
    risk_level: str,
):
    """Broadcast a risk score change to connected clients."""
    await ws_manager.broadcast("risk_events", {
        "type": "score_updated",
        "entity_id": entity_id,
        "old_score": old_score,
        "new_score": new_score,
        "risk_level": risk_level,
        "delta": round(new_score - old_score, 4),
    })


async def broadcast_security_event(event_type: str, entity_id: str, details: Dict[str, Any]):
    """Broadcast an ingested security event."""
    await ws_manager.broadcast("security_events", {
        "type": "event_ingested",
        "event_type": event_type,
        "entity_id": entity_id,
        "details": details,
    })


async def broadcast_simulation_complete(
    scenario_id: str,
    scenario_type: str,
    nodes_affected: int,
    max_risk: float,
):
    """Broadcast a simulation completion."""
    await ws_manager.broadcast("simulations", {
        "type": "simulation_complete",
        "scenario_id": scenario_id,
        "scenario_type": scenario_type,
        "nodes_affected": nodes_affected,
        "max_risk_increase": max_risk,
    })


async def broadcast_alert(
    entity_id: str,
    alert_type: str,
    severity: str,
    message: str,
):
    """Broadcast a high-risk alert."""
    await ws_manager.broadcast("alerts", {
        "type": "alert_triggered",
        "entity_id": entity_id,
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
    })


# =============================================================================
# WebSocket Endpoint
# =============================================================================

@router.websocket("/ws/risk-events")
async def risk_events_ws(
    websocket: WebSocket,
    rooms: str = Query(default="all", description="Comma-separated rooms"),
    token: Optional[str] = Query(default=None, description="JWT token"),
):
    """
    WebSocket endpoint for real-time risk events.
    
    Query params:
        rooms: Comma-separated list (risk_events,security_events,simulations,alerts,all)
        token: JWT auth token
    """
    # Parse rooms
    requested_rooms = [r.strip() for r in rooms.split(",")]
    valid_rooms = [r for r in requested_rooms if r in WebSocketManager.VALID_ROOMS]
    if not valid_rooms:
        valid_rooms = ["all"]
    
    # Validate JWT if provided
    user_info = None
    if token:
        try:
            from pdri.api.auth import decode_token
            user_info = decode_token(token)
        except Exception as e:
            logger.warning(f"WebSocket auth failed: {e}")
            await websocket.close(code=4001, reason="Invalid token")
            return
    
    await ws_manager.connect(websocket, valid_rooms, user_info)
    
    try:
        while True:
            # Listen for client messages (e.g. room subscribe/unsubscribe)
            data = await websocket.receive_json()
            msg_type = data.get("type")
            
            if msg_type == "pong":
                # Client acknowledged heartbeat
                pass
            elif msg_type == "subscribe":
                room = data.get("room")
                if room in WebSocketManager.VALID_ROOMS:
                    ws_manager._connections[room].add(websocket)
                    await websocket.send_json({
                        "type": "subscribed",
                        "room": room,
                    })
            elif msg_type == "unsubscribe":
                room = data.get("room")
                if room in ws_manager._connections:
                    ws_manager._connections[room].discard(websocket)
                    await websocket.send_json({
                        "type": "unsubscribed",
                        "room": room,
                    })
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await ws_manager.disconnect(websocket)
