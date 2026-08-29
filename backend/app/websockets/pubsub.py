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

_redis_client_instance: Optional[Redis] = None
_redis_unavailable: bool = False


def get_redis_client() -> Optional[Redis]:
    global _redis_client_instance, _redis_unavailable
    if _redis_unavailable:
        return None
    if _redis_client_instance is not None:
        return _redis_client_instance
    try:
        r = Redis.from_url(
            settings.get_redis_url(),
            decode_responses=True,
            socket_connect_timeout=0.2,
            socket_timeout=0.2,
        )
        r.ping()
        _redis_client_instance = r
        return _redis_client_instance
    except Exception:
        _redis_unavailable = True
        return None


def publish_realtime_event(envelope: RealtimeEventEnvelope):
    """Publish real-time event envelope to Redis Pub/Sub channel for multi-instance fan-out."""
    try:
        r = get_redis_client()
        if r:
            message_data = envelope.model_dump_json() if hasattr(envelope, "model_dump_json") else envelope.json()
            r.publish(REALTIME_PUBSUB_CHANNEL, message_data)
    except Exception as e:
        logger.warning(f"Failed to publish event to Redis Pub/Sub channel: {e}")


async def start_redis_pubsub_listener():
    """Background async task subscribing to Redis Pub/Sub channel and broadcasting messages to connected WebSockets."""
    logger.info("Starting Redis Pub/Sub real-time message listener loop...")
    while True:
        try:
            r = get_redis_client()
            if not r:
                await asyncio.sleep(5)
                continue

            pubsub = r.pubsub()
            pubsub.subscribe(REALTIME_PUBSUB_CHANNEL)

            while True:
                # Non-blocking async fetch from Redis PubSub
                message = await asyncio.to_thread(pubsub.get_message, ignore_subscribe_messages=True, timeout=0.5)
                if message and message.get("type") == "message":
                    raw_data = message.get("data")
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
                        elif envelope.type in ["ioc_created", "threat_feed_synced"]:
                            req_perm = Permission.THREAT_INTEL_READ
                        elif envelope.type in ["case_updated", "case_assigned", "evidence_added"]:
                            req_perm = Permission.CASES_READ
                        elif envelope.type == "approval_requested":
                            req_perm = Permission.PLAYBOOKS_APPROVE
                        elif envelope.type in [
                            "playbook_triggered",
                            "approval_approved",
                            "approval_rejected",
                            "response_started",
                            "response_action_completed",
                            "response_completed",
                            "response_failed",
                        ]:
                            req_perm = Permission.RESPONSES_READ

                        await ws_manager.broadcast(envelope, required_permission=req_perm)
                    except Exception as e:
                        logger.warning(f"Error parsing Pub/Sub message: {e}")

                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            logger.info("Redis Pub/Sub listener canceled.")
            break
        except Exception as e:
            logger.warning(f"Redis Pub/Sub listener disconnected ({e}), retrying in 5 seconds...")
            await asyncio.sleep(5)
