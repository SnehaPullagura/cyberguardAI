from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict


class RuleConditionSchema(BaseModel):
    category: str
    match_all: Optional[Dict[str, Any]] = None
    match_any: Optional[Dict[str, Any]] = None
    threshold: Optional[int] = 1
    timeframe_seconds: Optional[int] = 60


class DetectionRuleCreate(BaseModel):
    rule_id: str
    title: str
    description: Optional[str] = None
    severity: str  # critical, high, medium, low, info
    category: str  # authentication, network, process, file
    mitre_attack_id: Optional[str] = None
    condition: Dict[str, Any]
    raw_yaml: Optional[str] = None
    enabled: bool = True


class DetectionRuleUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    raw_yaml: Optional[str] = None
    enabled: Optional[bool] = None


class DetectionRuleRead(BaseModel):
    id: str
    rule_id: str
    title: str
    description: Optional[str] = None
    severity: str
    category: str
    mitre_attack_id: Optional[str] = None
    condition: Dict[str, Any]
    raw_yaml: Optional[str] = None
    enabled: bool
    author_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
