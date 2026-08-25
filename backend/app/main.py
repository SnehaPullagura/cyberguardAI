import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import User, Role, Permission, DetectionRule, ThreatIoC
from app.security.password import get_password_hash
from app.api.v1.router import api_v1_router
from app.websockets.pubsub import start_redis_pubsub_listener
from app.middleware.security import (
    CorrelationIdMiddleware,
    SecurityHeadersMiddleware,
    RateLimitationMiddleware,
    setup_security_exception_handlers,
)

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


def seed_initial_data(db: Session):
    """Seed initial Roles, Permissions, Admin account, Default Detection Rules, and Threat IoCs."""
    # 1. Seed Roles
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(
            name="admin",
            description="System Administrator with full security permissions",
        )
        db.add(admin_role)

    analyst_role = db.query(Role).filter(Role.name == "security_analyst").first()
    if not analyst_role:
        analyst_role = Role(
            name="security_analyst",
            description="SOC Analyst for investigating alerts and managing incidents",
        )
        db.add(analyst_role)

    viewer_role = db.query(Role).filter(Role.name == "viewer").first()
    if not viewer_role:
        viewer_role = Role(
            name="viewer",
            description="Read-only access to security dashboards and reports",
        )
        db.add(viewer_role)

    db.commit()

    # 2. Seed Default Superuser / Admin
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = User(
            username="admin",
            email="admin@cyberguard.ai",
            hashed_password=get_password_hash("AdminSecret123!"),
            role_id=admin_role.id,
            is_active=True,
            is_superuser=True,
        )
        db.add(admin_user)
        logger.info("Default admin user 'admin' created with password 'AdminSecret123!'")

    # 3. Seed Default Detection Rules
    rule1 = db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-AUTH-001").first()
    if not rule1:
        db.add(
            DetectionRule(
                rule_id="RULE-AUTH-001",
                title="Multiple SSH Authentication Failures (Potential Brute Force)",
                description="Detects SSH login failures originating from external source IP.",
                severity="high",
                category="authentication",
                mitre_attack_id="T1110",
                condition={
                    "category": "authentication",
                    "match_all": {"action": "login_failed"},
                },
                enabled=True,
            )
        )

    rule2 = db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-PROC-002").first()
    if not rule2:
        db.add(
            DetectionRule(
                rule_id="RULE-PROC-002",
                title="Encoded PowerShell Execution Detected",
                description="Detects powershell execution using -EncodedCommand flag.",
                severity="critical",
                category="process",
                mitre_attack_id="T1059.001",
                condition={
                    "category": "process",
                    "match_any": {
                        "process.command_line": "regex:.*-enc.*|.*-encodedcommand.*"
                    },
                },
                enabled=True,
            )
        )

    # 4. Seed Initial Threat Intelligence IoC
    ioc1 = db.query(ThreatIoC).filter(ThreatIoC.value == "198.51.100.42").first()
    if not ioc1:
        db.add(
            ThreatIoC(
                ioc_type="ip",
                value="198.51.100.42",
                threat_type="C2",
                confidence=0.95,
                source="AbuseCH",
                description="Known Malicious Command & Control Server",
                is_active=True,
            )
        )

    # 5. Seed Default Defensive Response Playbooks
    from app.models.playbook import Playbook
    pb1 = db.query(Playbook).filter(Playbook.playbook_id == "PB-DEFAULT-001").first()
    if not pb1:
        db.add(
            Playbook(
                playbook_id="PB-DEFAULT-001",
                name="High Risk Login Attack Containment",
                description="Automated incident creation, notification, and simulated account lock for high-risk authentication attacks.",
                enabled=True,
                response_mode="dry_run",
                severity_threshold="high",
                risk_score_threshold=75.0,
                trigger_conditions=[{"field": "risk_score", "operator": "gte", "value": 75.0}],
                action_sequence=[
                    {"action_type": "create_incident", "action_config": {}, "risk_level": "low"},
                    {"action_type": "notify_security_team", "action_config": {"channel": "soc-alerts"}, "risk_level": "low"},
                    {"action_type": "account_lock_simulation", "action_config": {}, "risk_level": "high"},
                ],
                approval_required=False,
                cooldown_seconds=300,
            )
        )

    pb2 = db.query(Playbook).filter(Playbook.playbook_id == "PB-DEFAULT-002").first()
    if not pb2:
        db.add(
            Playbook(
                playbook_id="PB-DEFAULT-002",
                name="Critical C2 Communication Isolation",
                description="Firewall blocking and host quarantine simulation for critical C2 detections.",
                enabled=True,
                response_mode="dry_run",
                severity_threshold="critical",
                risk_score_threshold=90.0,
                trigger_conditions=[{"field": "risk_score", "operator": "gte", "value": 90.0}],
                action_sequence=[
                    {"action_type": "create_incident", "action_config": {}, "risk_level": "low"},
                    {"action_type": "network_block_simulation", "action_config": {}, "risk_level": "critical"},
                    {"action_type": "quarantine_simulation", "action_config": {}, "risk_level": "high"},
                ],
                approval_required=True,
                cooldown_seconds=300,
            )
        )

    db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifespan context manager."""
    logger.info("Initializing CyberGuard AI Database Schemas...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_initial_data(db)
    finally:
        db.close()

    # Launch background Redis Pub/Sub listener for real-time WebSockets
    pubsub_task = asyncio.create_task(start_redis_pubsub_listener())
    yield
    pubsub_task.cancel()
    logger.info("Shutting down CyberGuard AI service...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="CyberGuard AI - Advanced Security Incident & Threat Detection Platform",
    lifespan=lifespan,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
)

# Register Security Middleware Stack
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitationMiddleware)
app.add_middleware(CorrelationIdMiddleware)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Exception Handlers
setup_security_exception_handlers(app)

# Register Router
app.include_router(api_v1_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_STR}/docs",
    }
