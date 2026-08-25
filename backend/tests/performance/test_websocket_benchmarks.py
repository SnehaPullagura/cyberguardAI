import time
import asyncio
from unittest import mock
from app.websockets.manager import WebSocketConnectionManager
from app.schemas.websocket import RealtimeEventEnvelope
from app.security.rbac import Permission


def test_websocket_broadcast_performance():
    """Benchmark WebSocketConnectionManager broadcast latency and throughput across concurrent socket clients."""
    async def _run():
        manager = WebSocketConnectionManager()
        client_counts = [10, 50]

        for count in client_counts:
            manager.active_connections = {}
            for i in range(count):
                mock_sock = mock.AsyncMock()
                await manager.connect(
                    connection_id=f"bm-conn-{i}",
                    websocket=mock_sock,
                    user_id=f"u-{i}",
                    username=f"user_{i}",
                    role="security_analyst",
                    permissions={Permission.EVENTS_READ, Permission.ALERTS_READ},
                )

            envelope = RealtimeEventEnvelope(
                type="security_event",
                data={"action": "test_login", "severity": "info"},
            )

            start = time.time()
            for _ in range(100):
                await manager.broadcast(envelope, required_permission=Permission.EVENTS_READ)

            duration = time.time() - start
            total_msgs = count * 100
            mps = total_msgs / duration if duration > 0 else total_msgs

            print(f"\n[WS BENCHMARK] Clients={count} | 100 Broadcasts ({total_msgs} msgs) | Duration={duration:.3f}s | Throughput={mps:.2f} msg/sec")
            assert duration < 5.0

    asyncio.run(_run())
