import { useMutation, useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { AnalyzeRequest } from '../types/api';

export const useStartAnalysis = () => {
  return useMutation({
    mutationFn: (request: AnalyzeRequest) => api.startAnalysis(request),
  });
};

export const useJobStatus = (jobId: string | null) => {
  return useQuery({
    queryKey: ['jobStatus', jobId],
    queryFn: () => {
      if (!jobId) throw new Error('No job ID provided');
      return api.getJobStatus(jobId);
    },
    enabled: !!jobId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === 'pending' || status === 'processing') return 2000;
      return false; // Stop polling on completion or failure
    },
  });
};

export const useJobResults = (jobId: string | null, isCompleted: boolean) => {
  return useQuery({
    queryKey: ['jobResults', jobId],
    queryFn: () => {
      if (!jobId) throw new Error('No job ID provided');
      return api.getJobResults(jobId);
    },
    enabled: !!jobId && isCompleted,
  });
};
