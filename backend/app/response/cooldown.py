import time
import logging
from typing import Dict, Any
from app.queue.redis_queue import redis_queue

logger = logging.getLogger(__name__)

# Fallback memory store for testing
_memory_cooldown_store: Dict[str, float] = {}


class CooldownManager:
    """Manages playbook execution locks and cooldown periods using Redis and DB fallback stores."""

    def check_and_acquire_lock(self, playbook_id: str, entity_id: str, cooldown_seconds: int = 300) -> bool:
        """Check if playbook execution for an entity is in cooldown. Returns True if lock acquired (can execute)."""
        key = f"cooldown:pb:{playbook_id}:entity:{entity_id}"
        now = time.time()

        # Check memory store fallback
        if key in _memory_cooldown_store:
            expire_time = _memory_cooldown_store[key]
            if now < expire_time:
                logger.info(f"Execution suppressed by active cooldown for key: {key}")
                return False  # Cooldown active, suppress execution!

        try:
            r = redis_queue.get_redis_client()
            acquired = r.set(f"lock:{key}", "1", ex=cooldown_seconds, nx=True)
            if not acquired:
                return False
        except Exception:
            _memory_cooldown_store[key] = now + cooldown_seconds

        return True


cooldown_manager = CooldownManager()
