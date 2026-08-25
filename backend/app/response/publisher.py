import logging
from typing import Dict, Any
from app.schemas.websocket import RealtimeEventEnvelope
from app.websockets.pubsub import publish_realtime_event

logger = logging.getLogger(__name__)


def publish_response_event(event_type: str, data: Dict[str, Any]):
    """Publish real-time playbook response engine event to Redis Pub/Sub."""
    try:
        envelope = RealtimeEventEnvelope(
            type=event_type,
            data=data,
        )
        publish_realtime_event(envelope)
    except Exception as e:
        logger.warning(f"Error publishing response event ({event_type}): {e}")
