export interface SecurityEvent {
  id: string;
  event_id: string;
  timestamp: string;
  source_type: string;
  category: string;
  action: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  observer_host?: string;
  observer_ip?: string;
  source_ip?: string;
  source_user?: string;
  destination_ip?: string;
  destination_host?: string;
  process_name?: string;
  raw_payload?: string;
  risk_score?: number;
  anomaly_score?: number;
}

export interface SecurityAlert {
  id: string;
  alert_id: string;
  timestamp: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  risk_score: number;
  status: 'open' | 'in_review' | 'resolved' | 'suppressed';
  source_entity?: string;
  detection_source: string;
}

export interface Incident {
  id: string;
  incident_id: string;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'new' | 'triaged' | 'investigating' | 'closed' | 'false_positive';
  risk_score: number;
  created_at: string;
  updated_at: string;
}

export interface DetectionRule {
  id: string;
  rule_id: string;
  title: string;
  description?: string;
  severity: string;
  category: string;
  enabled: boolean;
  created_at: string;
}

export interface DashboardSummary {
  total_events_processed: number;
  events_per_second: number;
  total_active_incidents: number;
  critical_incidents: number;
  open_alerts: number;
  high_risk_entities: Array<{
    entity_name: string;
    risk_score: number;
    alert_count: number;
  }>;
  alerts_by_severity: Record<string, number>;
  events_trend: Array<{ timestamp: string; count: number }>;
}

export type ConnectionStatus = 'CONNECTED' | 'CONNECTING' | 'RECONNECTING' | 'DISCONNECTED';

export interface RealtimeEventEnvelope {
  message_id: string;
  type: 'security_event' | 'alert_created' | 'alert_updated' | 'incident_created' | 'incident_updated' | 'dashboard_metric' | 'heartbeat' | 'system_status' | 'error';
  timestamp: string;
  correlation_id?: string;
  schema_version: string;
  data: Record<string, any>;
}
