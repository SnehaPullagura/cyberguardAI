import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from app.main import app


def test_websocket_missing_token_rejection():
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/api/v1/ws"):
            pass
    assert excinfo.value.code in [1008, 4008, 4001, 1000]


def test_websocket_authenticated_handshake(admin_token):
    client = TestClient(app)
    with client.websocket_connect(f"/api/v1/ws?token={admin_token}") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "system_status"
        assert data["data"]["status"] == "connected"
        assert data["data"]["role"] == "admin"

        # Send PING and receive PONG
        websocket.send_text("ping")
        pong = websocket.receive_json()
        assert pong["type"] == "heartbeat"
        assert pong["data"]["status"] == "pong"
