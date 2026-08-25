import uuid
import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.security.auth import decode_access_token
from app.security.rbac import get_role_permissions, Permission
from app.models import User, Role
from app.schemas.websocket import RealtimeEventEnvelope
from app.websockets.manager import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Real-Time WebSockets"])


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """Authenticated WebSocket endpoint supporting real-time event streaming, alerts, and live dashboard metrics."""
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing authentication token")
        return

    # Validate JWT Token
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired token")
        return

    user_id = payload["sub"]

    # Retrieve user and roles from DB
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User inactive or unauthorized")
            return

        role_name = user.role.name if user.role else "viewer"
        permissions = get_role_permissions(role_name)
    finally:
        db.close()

    connection_id = f"conn-{uuid.uuid4().hex[:8]}"
    await ws_manager.connect(
        connection_id=connection_id,
        websocket=websocket,
        user_id=user.id,
        username=user.username,
        role=role_name,
        permissions=permissions,
    )

    # Send initial welcome connection status envelope
    welcome_envelope = RealtimeEventEnvelope(
        type="system_status",
        data={
            "status": "connected",
            "connection_id": connection_id,
            "username": user.username,
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
