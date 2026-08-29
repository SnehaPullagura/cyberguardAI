import { apiClient } from './client';

export interface HuntQueryResult {
  status: string;
  query: string;
  query_type: string;
  sql_executed?: string;
  total_matches?: number;
  execution_time_ms?: number;
  columns?: string[];
  results?: any[];
  error_message?: string;
}

export interface ThreatHuntingPlaybook {
  hunt_id: string;
  title: string;
  hypothesis: string;
  mitre_tactic: string;
  mitre_technique: string;
  severity: string;
  confidence_level: number;
  kql_query: string;
  spl_query: string;
  analysis_steps: string[];
  remediation_recommendation: string;
}

export const threatHuntingApi = {
  executeQuery: async (query: string, queryType: string = 'kql', maxResults: number = 100): Promise<HuntQueryResult> => {
    const res = await apiClient.post('/hunting/query', {
      query,
      query_type: queryType,
      max_results: maxResults,
    });
    return res.data;
  },

  listPlaybooks: async (tactic?: string): Promise<ThreatHuntingPlaybook[]> => {
    const res = await apiClient.get('/hunting/playbooks', {
      params: tactic ? { tactic } : {},
    });
    return res.data;
  },

  runPlaybook: async (huntId: string): Promise<any> => {
    const res = await apiClient.post(`/hunting/playbooks/${huntId}/run`);
    return res.data;
  },
};
