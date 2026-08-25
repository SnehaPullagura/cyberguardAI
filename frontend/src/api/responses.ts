import { apiClient } from './client';
import { ResponseExecution, ResponseApproval } from '../types';

export const getResponses = async (statusFilter?: string): Promise<ResponseExecution[]> => {
  const response = await apiClient.get<ResponseExecution[]>('/responses', {
    params: { status_filter: statusFilter },
  });
  return response.data;
};

export const getPendingApprovals = async (): Promise<ResponseApproval[]> => {
  const response = await apiClient.get<ResponseApproval[]>('/responses/approvals');
  return response.data;
};

export const approveResponse = async (executionId: string, reason?: string): Promise<any> => {
  const response = await apiClient.post(`/responses/${executionId}/approve`, { reason });
  return response.data;
};

export const rejectResponse = async (executionId: string, reason?: string): Promise<any> => {
  const response = await apiClient.post(`/responses/${executionId}/reject`, { reason });
  return response.data;
};
