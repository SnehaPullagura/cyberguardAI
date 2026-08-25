import axios from 'axios';

const API_BASE = '/api/v1/reports';

const getHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    Authorization: token ? `Bearer ${token}` : '',
  };
};

export interface ComplianceEvaluationData {
  id: string;
  framework: string;
  overall_score: number;
  status: 'compliant' | 'needs_attention' | 'non_compliant';
  total_controls: number;
  passed_controls: number;
  warning_controls: number;
  failed_controls: number;
  summary_json: {
    framework_name: string;
    framework_description: string;
    controls: Array<{
      id: string;
      name: string;
      description: string;
      status: 'PASS' | 'WARNING' | 'FAIL';
      score: number;
      evidence: string;
    }>;
    evaluated_at: string;
  };
  evaluated_at: string;
}

export interface ReportScheduleData {
  id: string;
  name: string;
  report_type: string;
  framework?: string;
  frequency: string;
  recipients: string[];
  is_active: boolean;
  delivery_channel: string;
  next_run?: string;
  created_at: string;
}

export const fetchComplianceEvaluation = async (
  framework: string
): Promise<ComplianceEvaluationData> => {
  const res = await axios.get(`${API_BASE}/compliance/${framework}`, {
    headers: getHeaders(),
  });
  return res.data;
};

export const evaluateCompliance = async (
  framework: string
): Promise<ComplianceEvaluationData> => {
  const res = await axios.post(
    `${API_BASE}/compliance/${framework}/evaluate`,
    {},
    { headers: getHeaders() }
  );
  return res.data;
};

export const fetchComplianceHistory = async (
  framework?: string
): Promise<ComplianceEvaluationData[]> => {
  const res = await axios.get(`${API_BASE}/compliance-history`, {
    headers: getHeaders(),
    params: framework ? { framework } : {},
  });
  return res.data;
};

export const fetchReportSchedules = async (): Promise<ReportScheduleData[]> => {
  const res = await axios.get(`${API_BASE}/schedules`, {
    headers: getHeaders(),
  });
  return res.data;
};

export const createReportSchedule = async (payload: {
  name: string;
  report_type: string;
  framework?: string;
  frequency: string;
  recipients: string[];
  delivery_channel?: string;
}): Promise<ReportScheduleData> => {
  const res = await axios.post(`${API_BASE}/schedules`, payload, {
    headers: getHeaders(),
  });
  return res.data;
};

export const deleteReportSchedule = async (id: string): Promise<void> => {
  await axios.delete(`${API_BASE}/schedules/${id}`, {
    headers: getHeaders(),
  });
};
