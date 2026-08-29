import { apiClient } from './client';

export interface CISAVulnerability {
  cve_id: string;
  vendor: string;
  product: string;
  vulnerability_name: string;
  date_added: string;
  due_date: string;
  required_action: string;
  cvss_v3_score: number;
  epss_score: number;
  epss_percentile: number;
  ransomware_campaign_use: string;
}

export interface EnterpriseAsset {
  asset_id: string;
  hostname: string;
  ip_address: string;
  os: string;
  asset_type: string;
  criticality: string;
  exposure: string;
  software: Array<{ name: string; version: string }>;
  compliance_score: number;
}

export interface RemediationPlan {
  generated_at: string;
  total_assets_evaluated: number;
  total_remediations_required: number;
  critical_priority_count: number;
  high_priority_count: number;
  medium_priority_count: number;
  sla_compliance_rate: number;
  recommended_actions: Array<{
    action_id: string;
    asset_id: string;
    hostname: string;
    asset_criticality: string;
    cve_id: string;
    vulnerability_name: string;
    priority: string;
    composite_risk: number;
    epss_score: number;
    sla_deadline: string;
    recommended_action: string;
    estimated_remediation_time_mins: number;
    automation_status: string;
  }>;
}

export const postureApi = {
  getCisaKev: async (vendor?: string): Promise<CISAVulnerability[]> => {
    const res = await apiClient.get('/posture/cisa-kev', {
      params: vendor ? { vendor } : {},
    });
    return res.data;
  },

  getAssets: async (): Promise<EnterpriseAsset[]> => {
    const res = await apiClient.get('/posture/assets');
    return res.data;
  },

  scanAsset: async (assetId: string): Promise<any> => {
    const res = await apiClient.get(`/posture/assets/${assetId}/scan`);
    return res.data;
  },

  getRemediationPlan: async (): Promise<RemediationPlan> => {
    const res = await apiClient.get('/posture/remediation-plan');
    return res.data;
  },
};
