# Playbooks & Trigger Condition Specification

## Structure
Playbooks define conditions under which automated defensive responses are dispatched.

### Schema Fields
- `playbook_id`: Unique identifier (`PB-XXXXXXXX`)
- `name`: Human-readable name
- `description`: Operational intent and scope
- `enabled`: Boolean toggle
- `response_mode`: `dry_run`, `simulation`, `approval_required`, `authorized_execution`
- `severity_threshold`: Minimum alert severity required (`critical`, `high`, `medium`, `low`, `info`)
- `risk_score_threshold`: Minimum numerical risk score (`0.0` to `100.0`)
- `trigger_conditions`: List of structured condition objects
- `action_sequence`: Ordered list of allowlisted action configs
- `approval_required`: Boolean toggle forcing manual review
- `cooldown_seconds`: Minimum interval between consecutive runs on same entity
- `failure_policy`: `stop` (default) or `continue`

## Safe Trigger Evaluation
Arbitrary code execution or python expressions (`eval`, `exec`) are strictly prohibited. Conditions use structured schema:
```json
{
  "field": "risk_score",
  "operator": "gte",
  "value": 75.0
}
```

### Supported Operators
- `eq`: Equal to
- `ne`: Not equal to
- `gt`: Greater than
- `gte`: Greater than or equal to
- `lt`: Less than
- `lte`: Less than or equal to
- `contains`: Substring match (case-insensitive)
- `in`: Element in collection
