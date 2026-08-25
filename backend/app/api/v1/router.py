from fastapi import APIRouter
from app.api.v1 import (
    auth,
    events,
    rules,
    alerts,
    incidents,
    threat_intel,
    ml,
    dashboard,
    reports,
    audit,
)

api_v1_router = APIRouter()
api_v1_router.include_router(auth.router)
api_v1_router.include_router(events.router)
api_v1_router.include_router(rules.router)
api_v1_router.include_router(alerts.router)
api_v1_router.include_router(incidents.router)
api_v1_router.include_router(threat_intel.router)
api_v1_router.include_router(ml.router)
api_v1_router.include_router(dashboard.router)
api_v1_router.include_router(reports.router)
api_v1_router.include_router(audit.router)
