import time
import signal
import sys
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.schemas.event import SecurityEventCreate
from app.queue.redis_queue import redis_queue
from app.pipeline.processor import process_single_security_event

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] [CyberGuardWorker-%(process)d] %(message)s",
)
logger = logging.getLogger("cyberguard.worker")


class EventWorkerProcess:
    """Standalone background worker consuming security events from Redis queue."""

    def __init__(self):
        self.running = True
        self.max_retries = settings.MAX_RETRIES
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Register signal handlers for graceful shutdown on SIGINT and SIGTERM."""
        try:
            signal.signal(signal.SIGINT, self._handle_shutdown)
            signal.signal(signal.SIGTERM, self._handle_shutdown)
        except (ValueError, AttributeError):
            # Signal handling ignored if running in non-main thread
            pass

    def _handle_shutdown(self, signum, frame):
        logger.info(f"Received termination signal ({signum}). Initiating graceful worker shutdown...")
        self.running = False

    def process_event_dict(
        self, event_dict: Dict[str, Any], db: Optional[Session] = None
    ) -> bool:
        """Process a single event dictionary inside a DB session with retry handling."""
        event_id = event_dict.get("event_id", "unknown")
        retry_count = event_dict.get("retry_count", 0)

        own_session = False
        if db is None:
            db = SessionLocal()
            own_session = True

        start_time = time.time()
        try:
            event_schema = SecurityEventCreate.model_validate(event_dict)
            process_single_security_event(db, event_schema)
            duration_ms = (time.time() - start_time) * 1000
            logger.info(
                f"Successfully processed event_id={event_id} category={event_schema.category} action={event_schema.action} in {duration_ms:.2f}ms"
            )
            return True
        except Exception as e:
            db.rollback()
            logger.error(
                f"Processing error for event_id={event_id} (attempt {retry_count + 1}/{self.max_retries}): {e}"
            )
            if retry_count < self.max_retries:
                event_dict["retry_count"] = retry_count + 1
                time.sleep(0.1 * (2 ** retry_count))
                redis_queue.publish_events([SecurityEventCreate.model_validate(event_dict)])
            else:
                redis_queue.push_dlq(event_dict, error_reason=str(e))
            return False
        finally:
            if own_session:
                db.close()

    def run(self):
        """Worker main loop polling Redis queue."""
        logger.info(
            f"CyberGuard Event Worker started. Listening on queue '{settings.QUEUE_NAME}'..."
        )
        while self.running:
            try:
                event_dict = redis_queue.pop_event(timeout=1)
                if event_dict:
                    self.process_event_dict(event_dict)
            except Exception as e:
                logger.error(f"Unexpected worker loop exception: {e}")
                time.sleep(1)

        logger.info("Worker loop terminated cleanly. Shutdown complete.")


def main():
    worker = EventWorkerProcess()
    worker.run()


if __name__ == "__main__":
    main()
