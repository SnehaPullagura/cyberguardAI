import asyncio
from unittest import mock
from app.websockets.manager import WebSocketConnectionManager
from app.schemas.websocket import RealtimeEventEnvelope
from app.security.rbac import Permission


def test_websocket_manager_connect_and_disconnect():
    async def _run():
        manager = WebSocketConnectionManager()
        mock_socket = mock.AsyncMock()

        conn_id = "test-conn-1"
        await manager.connect(
            connection_id=conn_id,
            websocket=mock_socket,
            user_id="usr-123",
            username="analyst1",
            role="security_analyst",
            permissions={Permission.EVENTS_READ, Permission.ALERTS_READ},
        )

        assert manager.get_active_connection_count() == 1
        assert mock_socket.accept.called is True

        manager.disconnect(conn_id)
        assert manager.get_active_connection_count() == 0

    asyncio.run(_run())


def test_websocket_manager_rbac_broadcast():
    async def _run():
        manager = WebSocketConnectionManager()
        mock_socket_analyst = mock.AsyncMock()
        mock_socket_viewer = mock.AsyncMock()

        await manager.connect("conn-analyst", mock_socket_analyst, "u1", "analyst", "security_analyst", {Permission.EVENTS_READ, Permission.ALERTS_READ})
        await manager.connect("conn-viewer", mock_socket_viewer, "u2", "viewer", "viewer", {Permission.EVENTS_READ})

        envelope = RealtimeEventEnvelope(
            type="alert_created",
            data={"title": "Test Alert", "severity": "high"},
        )

        # Broadcast requiring ALERTS_READ permission
        await manager.broadcast(envelope, required_permission=Permission.ALERTS_READ)

        assert mock_socket_analyst.send_json.called is True
        assert mock_socket_viewer.send_json.called is False

    asyncio.run(_run())
