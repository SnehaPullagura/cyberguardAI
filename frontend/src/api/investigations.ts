import axios from 'axios';
import {
  InvestigationCase,
  CaseEvidence,
  CaseTimelineEvent,
  CaseNote,
  SavedSearch,
  EntityGraphData,
} from '../types';

const API_BASE = '/api/v1/investigations';

const getHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    Authorization: token ? `Bearer ${token}` : '',
  };
};

export const fetchCases = async (params?: {
  status?: string;
  priority?: string;
  severity?: string;
  assignee_id?: string;
}): Promise<InvestigationCase[]> => {
  const res = await axios.get(`${API_BASE}/cases`, {
    headers: getHeaders(),
    params,
  });
  return res.data;
};

export const fetchCase = async (caseId: string): Promise<InvestigationCase> => {
  const res = await axios.get(`${API_BASE}/cases/${caseId}`, {
    headers: getHeaders(),
  });
  return res.data;
};

export const createCase = async (payload: {
  title: string;
  description?: string;
  severity?: string;
  priority?: string;
  incident_id?: string;
  mitre_tactics?: string[];
  tags?: string[];
}): Promise<InvestigationCase> => {
  const res = await axios.post(`${API_BASE}/cases`, payload, {
    headers: getHeaders(),
  });
  return res.data;
};

export const updateCase = async (
  caseId: string,
  payload: Partial<InvestigationCase>
): Promise<InvestigationCase> => {
  const res = await axios.patch(`${API_BASE}/cases/${caseId}`, payload, {
    headers: getHeaders(),
  });
  return res.data;
};

export const assignCase = async (
  caseId: string,
  assigneeId: string
): Promise<InvestigationCase> => {
  const res = await axios.post(
    `${API_BASE}/cases/${caseId}/assign`,
    { assignee_id: assigneeId },
    { headers: getHeaders() }
  );
  return res.data;
};

export const fetchCaseTimeline = async (caseId: string): Promise<CaseTimelineEvent[]> => {
  const res = await axios.get(`${API_BASE}/cases/${caseId}/timeline`, {
    headers: getHeaders(),
  });
  return res.data;
};

export const fetchCaseGraph = async (caseId: string): Promise<EntityGraphData> => {
  const res = await axios.get(`${API_BASE}/cases/${caseId}/graph`, {
    headers: getHeaders(),
  });
  return res.data;
};

export const attachEvidence = async (
  caseId: string,
  payload: { evidence_type: string; title: string; data: Record<string, any> }
): Promise<CaseEvidence> => {
  const res = await axios.post(`${API_BASE}/cases/${caseId}/evidence`, payload, {
    headers: getHeaders(),
  });
  return res.data;
};

export const fetchCaseEvidence = async (caseId: string): Promise<CaseEvidence[]> => {
  const res = await axios.get(`${API_BASE}/cases/${caseId}/evidence`, {
    headers: getHeaders(),
  });
  return res.data;
};

export const addCaseNote = async (caseId: string, content: string): Promise<CaseNote> => {
  const res = await axios.post(
    `${API_BASE}/cases/${caseId}/notes`,
    { content },
    { headers: getHeaders() }
  );
  return res.data;
};

export const fetchCaseNotes = async (caseId: string): Promise<CaseNote[]> => {
  const res = await axios.get(`${API_BASE}/cases/${caseId}/notes`, {
    headers: getHeaders(),
  });
  return res.data;
};

export const globalSearch = async (query: string): Promise<Record<string, any>> => {
  const res = await axios.get(`${API_BASE}/search`, {
    headers: getHeaders(),
    params: { q: query },
  });
  return res.data;
};

export const fetchSavedSearches = async (): Promise<SavedSearch[]> => {
  const res = await axios.get(`${API_BASE}/saved-searches`, {
    headers: getHeaders(),
  });
  return res.data;
};
