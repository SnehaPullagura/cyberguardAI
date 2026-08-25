import json
import asyncio
import logging
from typing import Dict, List, Any, Optional, Set
from fastapi import WebSocket
from app.schemas.websocket import RealtimeEventEnvelope
from app.security.rbac import Permission, ROLE_PERMISSIONS

logger = logging.getLogger(__name__)


class WebSocketConnectionManager:
    """Centralized WebSocket connection manager with authentication tracking, heartbeat monitoring, and server-side RBAC permission filtering."""

    def __init__(self):
        self.active_connections: Dict[str, Dict[str, Any]] = {}

    async def connect(
        self,
        connection_id: str,
        websocket: WebSocket,
        user_id: str,
        username: str,
        role: str,
        permissions: Set[Permission],
    ):
        """Accept WebSocket connection and register authenticated connection state."""
        await websocket.accept()
        self.active_connections[connection_id] = {
            "socket": websocket,
            "user_id": user_id,
            "username": username,
            "role": role,
            "permissions": permissions,
            "message_count": 0,
        }
        logger.info(f"WebSocket client connected: conn_id={connection_id}, user={username}, role={role}")

    def disconnect(self, connection_id: str):
        """Remove disconnected client from active connections list."""
        if connection_id in self.active_connections:
            user = self.active_connections[connection_id]["username"]
            del self.active_connections[connection_id]
            logger.info(f"WebSocket client disconnected: conn_id={connection_id}, user={user}")

    async def send_personal_message(self, connection_id: str, envelope: RealtimeEventEnvelope):
        """Send message to a specific connection socket."""
        if connection_id in self.active_connections:
            sock: WebSocket = self.active_connections[connection_id]["socket"]
            try:
                payload_dict = json.loads(envelope.json())
                await sock.send_json(payload_dict)
            except Exception as e:
                logger.warning(f"Error sending personal message to {connection_id}: {e}")
                self.disconnect(connection_id)

    async def broadcast(
        self,
        envelope: RealtimeEventEnvelope,
        required_permission: Optional[Permission] = None,
    ):
        """Broadcast message to connected clients holding required RBAC permission."""
        disconnected = []
        payload_dict = json.loads(envelope.json())
        for conn_id, conn_info in list(self.active_connections.items()):
            if required_permission:
                user_perms: Set[Permission] = conn_info.get("permissions", set())
                if required_permission not in user_perms:
                    continue

            sock: WebSocket = conn_info["socket"]
            try:
                if conn_info["message_count"] > 500 and envelope.type not in ["alert_created", "incident_created"]:
                    continue

                await sock.send_json(payload_dict)
                conn_info["message_count"] += 1
            except Exception as e:
                logger.warning(f"WebSocket broadcast failed for {conn_id}: {e}")
                disconnected.append(conn_id)

        for conn_id in disconnected:
            self.disconnect(conn_id)

    def get_active_connection_count(self) -> int:
        return len(self.active_connections)


ws_manager = WebSocketConnectionManager()
