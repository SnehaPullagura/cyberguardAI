import uuid
import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status

from app.database import SessionLocal
from app.security.auth import decode_access_token
from app.security.rbac import get_role_permissions, Permission
from app.security.ws_ticket import validate_and_consume_ws_ticket
from app.models import User, Role
from app.schemas.websocket import RealtimeEventEnvelope
from app.websockets.manager import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Real-Time WebSockets"])


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    ticket: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
):
    """Authenticated WebSocket endpoint validating short-lived single-use tickets to establish secure sessions."""
    user_id = None
    role_name = "viewer"
    username = "unknown"

    # 1. Option 2: Primary Single-Use Ticket Validation
    if ticket:
        ticket_data = validate_and_consume_ws_ticket(ticket)
        if not ticket_data:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired ticket")
            return
        user_id = ticket_data.get("user_id")
        username = ticket_data.get("username", "unknown")
        role_name = ticket_data.get("role", "viewer")
    # Fallback to direct token if present
    elif token:
        payload = decode_access_token(token)
        if not payload or "sub" not in payload:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired token")
            return
        user_id = payload["sub"]
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if not user or not user.is_active:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User inactive")
                return
            role_name = user.role.name if user.role else "viewer"
            username = user.username
        finally:
            db.close()
    else:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing authentication ticket")
        return

    permissions = get_role_permissions(role_name)
    connection_id = f"conn-{uuid.uuid4().hex[:8]}"

    await ws_manager.connect(
        connection_id=connection_id,
        websocket=websocket,
        user_id=user_id,
        username=username,
        role=role_name,
        permissions=permissions,
    )

    # Send initial welcome connection status envelope
    welcome_envelope = RealtimeEventEnvelope(
        type="system_status",
        data={
            "status": "connected",
            "connection_id": connection_id,
            "username": username,
            "role": role_name,
        },
    )
    await ws_manager.send_personal_message(connection_id, welcome_envelope)

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping" or data == '{"type":"ping"}':
                pong_envelope = RealtimeEventEnvelope(
                    type="heartbeat",
                    data={"status": "pong"},
                )
                await ws_manager.send_personal_message(connection_id, pong_envelope)
    except WebSocketDisconnect:
        ws_manager.disconnect(connection_id)
    except Exception as e:
        logger.warning(f"WebSocket session error for {connection_id}: {e}")
        ws_manager.disconnect(connection_id)
