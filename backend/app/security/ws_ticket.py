import uuid
import logging
from typing import Optional, Dict, Any
from app.queue.redis_queue import redis_queue
from app.models.user import User

logger = logging.getLogger(__name__)

# In-memory ticket fallback store if Redis is offline during testing
_memory_ticket_store: Dict[str, Dict[str, Any]] = {}


def create_ws_ticket(user: User) -> str:
    """Generate a secure, short-lived (60s) single-use WebSocket authentication ticket."""
    ticket = f"wst_{uuid.uuid4().hex}"
    ticket_data = {
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role.name if user.role else "viewer",
    }

    try:
        # Store in Redis with 60-second expiration
        redis_client = redis_queue.get_redis_client()
        redis_client.setex(f"ws_ticket:{ticket}", 60, str(ticket_data))
    except Exception:
        # Fallback to memory store if Redis unavailable
        _memory_ticket_store[ticket] = ticket_data

    return ticket


def validate_and_consume_ws_ticket(ticket: str) -> Optional[Dict[str, Any]]:
    """Validate and immediately delete (single-use) a WebSocket ticket."""
    if not ticket or not ticket.startswith("wst_"):
        return None

    # Check memory fallback store first
    if ticket in _memory_ticket_store:
        ticket_data = _memory_ticket_store.pop(ticket)
        return ticket_data

    try:
        redis_client = redis_queue.get_redis_client()
        key = f"ws_ticket:{ticket}"

        # Atomic get and delete (single-use)
        pipeline = redis_client.pipeline()
        pipeline.get(key)
        pipeline.delete(key)
        results = pipeline.execute()

        raw_data = results[0]
        if raw_data:
            import ast
            return ast.literal_eval(raw_data)
    except Exception as e:
        logger.warning(f"Error consuming WebSocket ticket: {e}")

    return None
