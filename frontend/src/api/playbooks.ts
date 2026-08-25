import { apiClient } from './client';
import { Playbook } from '../types';

export const getPlaybooks = async (enabledOnly = false): Promise<Playbook[]> => {
  const response = await apiClient.get<Playbook[]>('/playbooks', {
    params: { enabled_only: enabledOnly },
  });
  return response.data;
};

export const getPlaybook = async (id: string): Promise<Playbook> => {
  const response = await apiClient.get<Playbook>(`/playbooks/${id}`);
  return response.data;
};

export const testPlaybook = async (id: string, mockPayload: any = {}): Promise<any> => {
  const response = await apiClient.post(`/playbooks/${id}/test`, mockPayload);
  return response.data;
};

export const enablePlaybook = async (id: string): Promise<Playbook> => {
  const response = await apiClient.post<Playbook>(`/playbooks/${id}/enable`);
  return response.data;
};

export const disablePlaybook = async (id: string): Promise<Playbook> => {
  const response = await apiClient.post<Playbook>(`/playbooks/${id}/disable`);
  return response.data;
};
