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

export interface Playbook {
  id: string;
  playbook_id: string;
  name: string;
  description?: string;
  enabled: boolean;
  response_mode: 'dry_run' | 'simulation' | 'approval_required' | 'authorized_execution';
  severity_threshold: string;
  risk_score_threshold: number;
  trigger_conditions: Array<Record<string, any>>;
  action_sequence: Array<Record<string, any>>;
  approval_required: boolean;
  cooldown_seconds: number;
  created_at: string;
}

export interface ResponseActionExecution {
  id: string;
  action_type: string;
  status: string;
  mode: string;
  started_at: string;
  completed_at?: string;
  duration_ms: number;
  verification_status: string;
  error_message?: string;
}

export interface ResponseApproval {
  id: string;
  approval_id: string;
  execution_id: string;
  incident_id?: string;
  playbook_id?: string;
  action_type: string;
  risk_level: string;
  requested_at: string;
  decision: 'pending' | 'approved' | 'rejected' | 'expired';
  reason?: string;
}

export interface ResponseExecution {
  id: string;
  execution_id: string;
  playbook_id?: string;
  incident_id?: string;
  alert_id?: string;
  status: 'pending_approval' | 'approved' | 'running' | 'success' | 'failed' | 'simulated' | 'rejected' | 'cancelled';
  mode: 'dry_run' | 'simulation' | 'approval_required' | 'authorized_execution';
  started_at: string;
  completed_at?: string;
  duration_ms: number;
  triggered_by: string;
  action_executions?: ResponseActionExecution[];
  approval_requests?: ResponseApproval[];
}

export interface RealtimeEventEnvelope {
  message_id: string;
  type:
    | 'security_event'
    | 'alert_created'
    | 'alert_updated'
    | 'incident_created'
    | 'incident_updated'
    | 'dashboard_metric'
    | 'heartbeat'
    | 'system_status'
    | 'error'
    | 'playbook_triggered'
    | 'approval_requested'
    | 'approval_approved'
    | 'approval_rejected'
    | 'response_started'
    | 'response_action_completed'
    | 'response_completed'
    | 'response_failed'
    | 'ioc_created'
    | 'threat_feed_synced'
    | 'case_updated'
    | 'case_assigned'
    | 'evidence_added';
  timestamp: string;
  correlation_id?: string;
  schema_version: string;
  data: Record<string, any>;
}

export interface InvestigationCase {
  id: string;
  case_id: string;
  title: string;
  description?: string;
  status: 'open' | 'investigating' | 'contained' | 'closed' | 'false_positive';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  severity: 'critical' | 'high' | 'medium' | 'low';
  incident_id?: string;
  assignee_id?: string;
  created_by_id?: string;
  mitre_tactics?: string[];
  tags?: string[];
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

export interface CaseEvidence {
  id: string;
  case_id: string;
  evidence_type: string;
  title: string;
  data: Record<string, any>;
  added_by_id?: string;
  created_at: string;
}

export interface CaseTimelineEvent {
  id: string;
  case_id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description?: string;
  actor?: string;
  metadata_json?: Record<string, any>;
}

export interface CaseNote {
  id: string;
  case_id: string;
  author_id: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface SavedSearch {
  id: string;
  name: string;
  description?: string;
  user_id: string;
  target_entity: string;
  filter_params: Record<string, any>;
  created_at: string;
}

export interface EntityGraphNode {
  id: string;
  label: string;
  type: string;
  properties?: Record<string, any>;
}

export interface EntityGraphEdge {
  source: string;
  target: string;
  relationship: string;
}

export interface EntityGraphData {
  case_id: string;
  nodes: EntityGraphNode[];
  edges: EntityGraphEdge[];
  nodes_count: number;
  edges_count: number;
}
