# WebSocket JSON Envelope Protocol

## Message Schema (`RealtimeEventEnvelope`)
```json
{
  "message_id": "msg-uuid-1234",
  "type": "security_event | alert_created | alert_updated | incident_created | incident_updated | dashboard_metric | heartbeat | system_status | error",
  "timestamp": "2026-08-25T12:00:00Z",
  "correlation_id": "corr-uuid-5678",
  "schema_version": "1.0",
  "data": { ... }
}
```
