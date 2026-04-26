import axios from 'axios';
import type { AnalyzeRequest, JobStatusResponse, AnalysisResultsResponse } from '../types/api';

const apiClient = axios.create({
  baseURL: 'http://localhost:8000/api', // Adjust if FastAPI runs on a different port
  headers: {
    'Content-Type': 'application/json',
  },
});

export const api = {
  startAnalysis: async (request: AnalyzeRequest): Promise<{ job_id: string; message: string }> => {
    const response = await apiClient.post('/analyze/github', request);
    return response.data;
  },

  getJobStatus: async (jobId: string): Promise<JobStatusResponse> => {
    const response = await apiClient.get(`/analyze/status/${jobId}`);
    return response.data;
  },

  getJobResults: async (jobId: string): Promise<AnalysisResultsResponse> => {
    const response = await apiClient.get(`/analyze/results/${jobId}`);
    return response.data;
  },

  getJobLogs: async (jobId: string, since = 0): Promise<{ logs: { ts: string; level: string; msg: string }[]; total: number }> => {
    const response = await apiClient.get(`/analyze/logs/${jobId}`, { params: { since } });
    return response.data;
  },
};
