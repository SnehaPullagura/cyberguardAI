import json
import asyncio
import logging
from typing import Optional
from redis import Redis
from app.config import settings
from app.schemas.websocket import RealtimeEventEnvelope
from app.websockets.manager import ws_manager
from app.security.rbac import Permission

logger = logging.getLogger(__name__)

REALTIME_PUBSUB_CHANNEL = "cyberguard:realtime:events"


def get_redis_client() -> Redis:
    return Redis.from_url(settings.get_redis_url(), decode_responses=True)


def publish_realtime_event(envelope: RealtimeEventEnvelope):
    """Publish real-time event envelope to Redis Pub/Sub channel for multi-instance fan-out."""
    try:
        r = get_redis_client()
        message_data = envelope.json()
        r.publish(REALTIME_PUBSUB_CHANNEL, message_data)
    except Exception as e:
        logger.warning(f"Failed to publish event to Redis Pub/Sub channel: {e}")


async def start_redis_pubsub_listener():
    """Background async task subscribing to Redis Pub/Sub channel and broadcasting messages to connected WebSockets."""
    logger.info("Starting Redis Pub/Sub real-time message listener loop...")
    while True:
        try:
            r = get_redis_client()
            pubsub = r.pubsub()
            pubsub.subscribe(REALTIME_PUBSUB_CHANNEL)

            for item in pubsub.listen():
                if item["type"] == "message":
                    raw_data = item["data"]
                    try:
                        data_dict = json.loads(raw_data)
                        envelope = RealtimeEventEnvelope(**data_dict)

                        # Determine required RBAC permission based on message type
                        req_perm: Optional[Permission] = None
                        if envelope.type == "security_event":
                            req_perm = Permission.EVENTS_READ
                        elif envelope.type in ["alert_created", "alert_updated"]:
                            req_perm = Permission.ALERTS_READ
                        elif envelope.type in ["incident_created", "incident_updated"]:
                            req_perm = Permission.INCIDENTS_READ

                        await ws_manager.broadcast(envelope, required_permission=req_perm)
                    except Exception as e:
                        logger.warning(f"Error parsing Pub/Sub message: {e}")

                await asyncio.sleep(0.01)
        except Exception as e:
            logger.warning(f"Redis Pub/Sub listener disconnected ({e}), retrying in 5 seconds...")
            await asyncio.sleep(5)
