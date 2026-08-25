import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, JSON, Text, Index, Float
from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(100), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, primary_key=True, default=datetime.utcnow, nullable=False, index=True)
    ingested_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    source_type = Column(String(50), nullable=False, index=True)  # syslog, winevent, nginx, cloudtrail, etc.
    category = Column(String(50), nullable=False, index=True)     # authentication, network, process, file, etc.
    action = Column(String(100), nullable=False)                 # login_failed, connection_accepted, process_created
    severity = Column(String(20), nullable=False, index=True)     # critical, high, medium, low, info

    observer_host = Column(String(255), nullable=True)
    observer_ip = Column(String(45), nullable=True, index=True)

    source_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    source_user = Column(String(100), nullable=True, index=True)
    source_domain = Column(String(100), nullable=True)

    destination_ip = Column(String(45), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)
    destination_host = Column(String(255), nullable=True)

    process_name = Column(String(255), nullable=True)
    process_pid = Column(Integer, nullable=True)
    process_command_line = Column(Text, nullable=True)
    process_hash = Column(String(128), nullable=True)

    risk_score = Column(Float, nullable=True, default=0.0)
    anomaly_score = Column(Float, nullable=True, default=0.0)

    raw_payload = Column(Text, nullable=True)
    normalized_payload = Column(JSON, nullable=True)

    __table_args__ = (
        Index("idx_events_timestamp_category", "timestamp", "category"),
        Index("idx_events_timestamp_severity", "timestamp", "severity"),
        Index("idx_events_timestamp_source_type", "timestamp", "source_type"),
        Index("idx_events_source_dest_ip", "source_ip", "destination_ip"),
        Index("idx_events_keyset_pagination", "timestamp", "id"),
    )
