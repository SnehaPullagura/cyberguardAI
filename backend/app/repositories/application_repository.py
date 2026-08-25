from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.rule import DetectionRule
from app.models.threat_intel import ThreatIoC
from app.models.audit import AuditLog
from app.repositories.base import BaseRepository


class ApplicationRepository:
    """Transactional Application Data Access Repository for PostgreSQL application entities."""

    def __init__(self):
        self.users = BaseRepository[User](User)
        self.alerts = BaseRepository[Alert](Alert)
        self.incidents = BaseRepository[Incident](Incident)
        self.rules = BaseRepository[DetectionRule](DetectionRule)
        self.iocs = BaseRepository[ThreatIoC](ThreatIoC)
        self.audit_logs = BaseRepository[AuditLog](AuditLog)

    def get_open_alerts_count(self, db: Session) -> int:
        return db.query(Alert).filter(Alert.status.in_(["new", "investigating"])).count()

    def get_active_incidents_count(self, db: Session) -> int:
        return db.query(Incident).filter(Incident.status.in_(["new", "in_progress"])).count()


application_repository = ApplicationRepository()
