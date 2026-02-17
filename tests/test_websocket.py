"""
Tests for WebSocket Manager
=============================

Tests WebSocket connection management, room subscriptions,
broadcasting, and client messaging.
"""

import sys
from unittest.mock import MagicMock, AsyncMock, patch

# Mock neo4j before any PDRI imports
if "neo4j" not in sys.modules:
    sys.modules["neo4j"] = MagicMock()
    sys.modules["neo4j.exceptions"] = MagicMock()

import pytest
from pdri.api.websocket import (
    WebSocketManager,
    broadcast_score_update,
    broadcast_security_event,
    broadcast_simulation_complete,
    broadcast_alert,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def manager():
    """Create a fresh WebSocketManager."""
    return WebSocketManager()


@pytest.fixture
def mock_ws():
    """Create a mock WebSocket connection."""
    from starlette.websockets import WebSocketState
    
    ws = AsyncMock()
    ws.client_state = WebSocketState.CONNECTED
    ws.accept = AsyncMock()
    ws.send_json = AsyncMock()
    ws.close = AsyncMock()
    return ws


@pytest.fixture
def mock_ws2():
    """Create a second mock WebSocket."""
    from starlette.websockets import WebSocketState
    
    ws = AsyncMock()
    ws.client_state = WebSocketState.CONNECTED
    ws.accept = AsyncMock()
    ws.send_json = AsyncMock()
    ws.close = AsyncMock()
    return ws


# =============================================================================
# Tests
# =============================================================================

class TestWebSocketManager:
    """Test suite for WebSocket connection management."""
    
    def test_valid_rooms(self, manager):
        """Test that valid rooms are defined."""
        assert "risk_events" in manager.VALID_ROOMS
        assert "security_events" in manager.VALID_ROOMS
        assert "simulations" in manager.VALID_ROOMS
        assert "alerts" in manager.VALID_ROOMS
        assert "all" in manager.VALID_ROOMS
    
    def test_initial_state(self, manager):
        """Test manager starts with no connections."""
        assert manager.total_connections == 0
    
    @pytest.mark.asyncio
    async def test_connect(self, manager, mock_ws):
        """Test connecting a WebSocket."""
        await manager.connect(mock_ws, ["risk_events"], {"sub": "user-1"})
        
        assert manager.total_connections == 1
        mock_ws.accept.assert_called_once()
        mock_ws.send_json.assert_called_once()  # welcome message
    
    @pytest.mark.asyncio
    async def test_connect_multiple_rooms(self, manager, mock_ws):
        """Test subscribing to multiple rooms."""
        await manager.connect(mock_ws, ["risk_events", "alerts"])
        
        assert mock_ws in manager._connections["risk_events"]
        assert mock_ws in manager._connections["alerts"]
        assert mock_ws not in manager._connections["simulations"]
    
    @pytest.mark.asyncio
    async def test_disconnect(self, manager, mock_ws):
        """Test disconnecting removes from all rooms."""
        await manager.connect(mock_ws, ["risk_events", "alerts"])
        assert manager.total_connections == 1
        
        await manager.disconnect(mock_ws)
        assert manager.total_connections == 0
    
    @pytest.mark.asyncio
    async def test_broadcast(self, manager, mock_ws, mock_ws2):
        """Test broadcasting to a room."""
        await manager.connect(mock_ws, ["risk_events"])
        await manager.connect(mock_ws2, ["alerts"])
        
        await manager.broadcast("risk_events", {"type": "score_updated"})
        
        # mock_ws is in risk_events, should receive
        assert mock_ws.send_json.call_count >= 2  # welcome + broadcast
        # mock_ws2 is only in alerts, should not receive (beyond welcome)
        assert mock_ws2.send_json.call_count == 1  # welcome only
    
    @pytest.mark.asyncio
    async def test_broadcast_to_all(self, manager, mock_ws, mock_ws2):
        """Test 'all' room subscribers get every broadcast."""
        await manager.connect(mock_ws, ["all"])
        await manager.connect(mock_ws2, ["risk_events"])
        
        await manager.broadcast("risk_events", {"type": "test"})
        
        # Both should receive (mock_ws via "all", mock_ws2 via "risk_events")
        assert mock_ws.send_json.call_count >= 2
        assert mock_ws2.send_json.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_send_to_user(self, manager, mock_ws, mock_ws2):
        """Test sending message to a specific user."""
        await manager.connect(mock_ws, ["all"], {"sub": "user-1"})
        await manager.connect(mock_ws2, ["all"], {"sub": "user-2"})
        
        await manager.send_to_user("user-1", {"type": "private"})
        
        # Only user-1 should get the private message
        user1_calls = mock_ws.send_json.call_count
        user2_calls = mock_ws2.send_json.call_count
        assert user1_calls > user2_calls
    
    def test_heartbeat_interval(self):
        """Test heartbeat interval is set."""
        assert WebSocketManager.HEARTBEAT_INTERVAL == 30
    
    @pytest.mark.asyncio
    async def test_invalid_room_ignored(self, manager, mock_ws):
        """Test that invalid room names are silently ignored."""
        await manager.connect(mock_ws, ["invalid_room", "risk_events"])
        
        assert mock_ws in manager._connections["risk_events"]
        assert "invalid_room" not in manager._connections


class TestBroadcastHelpers:
    """Test broadcast convenience functions."""
    
    @pytest.mark.asyncio
    async def test_broadcast_score_update(self):
        """Test score update broadcast message."""
        with patch("pdri.api.websocket.ws_manager") as mock_mgr:
            mock_mgr.broadcast = AsyncMock()
            await broadcast_score_update("node-001", 0.5, 0.8, "high")
            
            mock_mgr.broadcast.assert_called_once()
            args = mock_mgr.broadcast.call_args
            assert args[0][0] == "risk_events"
            assert args[0][1]["type"] == "score_updated"
            assert args[0][1]["entity_id"] == "node-001"
    
    @pytest.mark.asyncio
    async def test_broadcast_security_event(self):
        """Test security event broadcast."""
        with patch("pdri.api.websocket.ws_manager") as mock_mgr:
            mock_mgr.broadcast = AsyncMock()
            await broadcast_security_event("data_movement", "db-1", {"count": 5})
            
            mock_mgr.broadcast.assert_called_once()
            args = mock_mgr.broadcast.call_args
            assert args[0][0] == "security_events"
    
    @pytest.mark.asyncio
    async def test_broadcast_simulation_complete(self):
        """Test simulation complete broadcast."""
        with patch("pdri.api.websocket.ws_manager") as mock_mgr:
            mock_mgr.broadcast = AsyncMock()
            await broadcast_simulation_complete("sim-1", "vendor_compromise", 10, 0.45)
            
            mock_mgr.broadcast.assert_called_once()
            args = mock_mgr.broadcast.call_args
            assert args[0][0] == "simulations"
    
    @pytest.mark.asyncio
    async def test_broadcast_alert(self):
        """Test alert broadcast."""
        with patch("pdri.api.websocket.ws_manager") as mock_mgr:
            mock_mgr.broadcast = AsyncMock()
            await broadcast_alert("node-001", "high_risk", "critical", "Score spiked")
            
            mock_mgr.broadcast.assert_called_once()
            args = mock_mgr.broadcast.call_args
            assert args[0][0] == "alerts"
