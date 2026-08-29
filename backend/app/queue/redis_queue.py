import json
import logging
from typing import List, Dict, Any, Optional, Tuple
import redis
from app.config import settings
from app.schemas.event import SecurityEventCreate

logger = logging.getLogger(__name__)


class RedisQueueManager:
    """Manages Redis connection, event queue operations, idempotency, and DLQ routing."""

    def __init__(self):
        self.queue_name = settings.QUEUE_NAME
        self.dlq_name = settings.DLQ_NAME
        self.max_retries = settings.MAX_RETRIES
        self.idempotency_ttl = settings.EVENT_IDEMPOTENCY_TTL_SECONDS
        self._in_memory_queue: List[Dict[str, Any]] = []
        self._in_memory_processed: set = set()
        self._redis_client: Optional[redis.Redis] = None
        self._redis_disabled: bool = False

    def reset_state(self):
        """Reset in-memory queue and processed sets between test executions."""
        self._in_memory_queue.clear()
        self._in_memory_processed.clear()
        self._redis_disabled = False
        try:
            client = self.get_client()
            if client:
                client.delete(self.queue_name, self.dlq_name)
                keys = client.keys("cyberguard:events:processed:*")
                if keys:
                    client.delete(*keys)
        except Exception:
            pass

    def get_client(self) -> Optional[redis.Redis]:
        """Lazy initialization of Redis client connection with fast failure timeout."""
        if self._redis_disabled:
            return None

        if self._redis_client is not None:
            try:
                self._redis_client.ping()
                return self._redis_client
            except Exception:
                self._redis_client = None

        try:
            client = redis.from_url(
                settings.get_redis_url(),
                socket_timeout=0.2,
                socket_connect_timeout=0.2,
                decode_responses=True,
            )
            client.ping()
            self._redis_client = client
            return self._redis_client
        except Exception as e:
            self._redis_disabled = True
            logger.info(f"Redis not available at {settings.get_redis_url()} ({e}). Using in-memory queue fallback.")
            return None

    def is_duplicate_and_mark(self, event_id: str) -> bool:
        """Check if event_id has already been enqueued/processed. Returns True if duplicate."""
        if not event_id:
            return False

        client = self.get_client()
        key = f"cyberguard:events:processed:{event_id}"

        if client:
            try:
                is_new = client.set(key, "1", nx=True, ex=self.idempotency_ttl)
                return not is_new
            except Exception as e:
                logger.warning(f"Redis idempotency check error ({e}), checking in-memory.")

        if event_id in self._in_memory_processed:
            return True
        self._in_memory_processed.add(event_id)
        return False

    def publish_events(
        self, events: List[SecurityEventCreate]
    ) -> Tuple[int, List[str]]:
        """Serialize and publish security events to Redis queue. Returns (enqueued_count, enqueued_ids)."""
        client = self.get_client()
        enqueued_ids: List[str] = []

        for event in events:
            if not event.event_id:
                import uuid
                event.event_id = str(uuid.uuid4())

            # Check idempotency
            if self.is_duplicate_and_mark(event.event_id):
                logger.info(f"Skipping duplicate event {event.event_id}")
                continue

            event_dict = event.model_dump(mode="json")
            event_dict["retry_count"] = 0

            if client:
                try:
                    payload_json = json.dumps(event_dict)
                    client.rpush(self.queue_name, payload_json)
                    enqueued_ids.append(event.event_id)
                except Exception as e:
                    logger.error(f"Redis RPUSH failed for event {event.event_id}: {e}")
                    self._in_memory_queue.append(event_dict)
                    enqueued_ids.append(event.event_id)
            else:
                self._in_memory_queue.append(event_dict)
                enqueued_ids.append(event.event_id)

        return len(enqueued_ids), enqueued_ids

    def pop_event(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        """Pop next event dictionary from queue (Redis or in-memory fallback)."""
        client = self.get_client()

        if client:
            try:
                item = client.blpop(self.queue_name, timeout=timeout)
                if item:
                    _, payload_json = item
                    return json.loads(payload_json)
            except Exception as e:
                logger.warning(f"Redis BLPOP error ({e}), popping from in-memory fallback.")

        if self._in_memory_queue:
            return self._in_memory_queue.pop(0)

        return None

    def push_dlq(self, event_dict: Dict[str, Any], error_reason: str):
        """Route failed event to Dead Letter Queue after max retries exceeded."""
        event_dict["dlq_reason"] = error_reason
        client = self.get_client()

        if client:
            try:
                client.rpush(self.dlq_name, json.dumps(event_dict))
                logger.error(
                    f"Event {event_dict.get('event_id')} pushed to DLQ ({self.dlq_name}): {error_reason}"
                )
                return
            except Exception as e:
                logger.error(f"Failed to push to Redis DLQ: {e}")

        logger.error(f"Event {event_dict.get('event_id')} logged to DLQ in-memory: {error_reason}")

    def get_health(self) -> Dict[str, Any]:
        """Check Redis connectivity and queue depth metrics."""
        client = self.get_client()
        if client:
            try:
                queue_length = client.llen(self.queue_name)
                dlq_length = client.llen(self.dlq_name)
                return {
                    "status": "healthy",
                    "mode": "redis",
                    "queue_length": queue_length,
                    "dlq_length": dlq_length,
                }
            except Exception as e:
                return {
                    "status": "degraded",
                    "mode": "in_memory_fallback",
                    "error": str(e),
                    "queue_length": len(self._in_memory_queue),
                    "dlq_length": 0,
                }

        return {
            "status": "fallback",
            "mode": "in_memory_fallback",
            "queue_length": len(self._in_memory_queue),
            "dlq_length": 0,
        }


redis_queue = RedisQueueManager()
