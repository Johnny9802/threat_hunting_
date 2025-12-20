import axios from 'axios';
import type { Playbook, SearchFilters, APIStats, ExportResponse, AIResponse } from '../types/playbook';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Health check
export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

// Playbooks
export const getPlaybooks = async (limit?: number, offset?: number): Promise<Playbook[]> => {
  const response = await api.get('/playbooks', {
    params: { limit, offset },
  });
  return response.data;
};

export const getPlaybook = async (id: string): Promise<Playbook> => {
  const response = await api.get(`/playbooks/${id}`);
  return response.data;
};

export const searchPlaybooks = async (filters: SearchFilters): Promise<Playbook[]> => {
  const response = await api.get('/search', {
    params: filters,
  });
  return response.data;
};

// Export
export const exportQuery = async (playbookId: string, siem: string): Promise<ExportResponse> => {
  const response = await api.get(`/playbooks/${playbookId}/export/${siem}`);
  return response.data;
};

// MITRE
export const getTactics = async (): Promise<string[]> => {
  const response = await api.get('/mitre/tactics');
  return response.data;
};

export const getTechnique = async (techniqueId: string) => {
  const response = await api.get(`/mitre/techniques/${techniqueId}`);
  return response.data;
};

// AI
export const explainPlaybook = async (playbookId: string): Promise<AIResponse> => {
  const response = await api.post('/ai/explain', { playbook_id: playbookId });
  return response.data;
};

export const askQuestion = async (question: string): Promise<AIResponse> => {
  const response = await api.post('/ai/ask', { question });
  return response.data;
};

export const suggestNextSteps = async (finding: string, playbookId?: string): Promise<AIResponse> => {
  const response = await api.post('/ai/suggest', { finding, playbook_id: playbookId });
  return response.data;
};

export const generateVariant = async (
  playbookId: string,
  targetEnv: string,
  targetSiem: string
): Promise<AIResponse> => {
  const response = await api.post('/ai/generate', {
    playbook_id: playbookId,
    target_env: targetEnv,
    target_siem: targetSiem,
  });
  return response.data;
};

// Stats
export const getStats = async (): Promise<APIStats> => {
  const response = await api.get('/stats');
  return response.data;
};

export default api;
