import time
import uuid
from datetime import datetime, timedelta
from app.models.event import SecurityEvent
from app.repositories.event_repository import event_repository


def test_progressive_event_insertion_and_query_benchmarks(db_session):
    """Progressive performance benchmark measuring event insertion throughput (EPS) and keyset pagination latency."""
    scales = [100, 500]  # Progressive batch sizes for unit test benchmarking

    for scale in scales:
        start_time = time.time()
        now = datetime.utcnow()

        for i in range(scale):
            ev = SecurityEvent(
                event_id=f"bm-{scale}-{i}-{uuid.uuid4().hex[:4]}",
                timestamp=now - timedelta(seconds=i),
                source_type="syslog",
                category="authentication",
                action="login_failed",
                severity="medium",
                source_ip="192.168.1.50",
            )
            event_repository.save_event(db_session, ev)

        db_session.commit()
        duration = time.time() - start_time
        eps = scale / duration if duration > 0 else scale

        # Measure Keyset Pagination Latency
        q_start = time.time()
        events, next_cursor = event_repository.search_events_keyset(db_session, limit=50)
        q_duration_ms = (time.time() - q_start) * 1000

        print(
            f"\n[BENCHMARK] Scale={scale} Events | Duration={duration:.3f}s | Throughput={eps:.2f} EPS | KeysetQuery={q_duration_ms:.2f}ms"
        )
        assert len(events) <= 50
