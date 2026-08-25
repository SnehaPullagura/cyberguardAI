import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Text, Boolean, Integer, JSON
from app.database import Base


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    feed_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    feed_type = Column(String(50), default="taxii21", nullable=False)  # taxii21, stix_json, abusech, alienvault, custom_json
    url = Column(String(1024), nullable=False)
    api_key = Column(String(255), nullable=True)
    collection_id = Column(String(255), nullable=True)
    
    poll_interval_minutes = Column(Integer, default=60, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    confidence_weight = Column(Float, default=0.85, nullable=False)
    
    last_sync = Column(DateTime, nullable=True)
    last_status = Column(String(30), default="healthy", nullable=False)  # healthy, error, syncing
    last_error = Column(Text, nullable=True)
    ioc_count = Column(Integer, default=0, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
