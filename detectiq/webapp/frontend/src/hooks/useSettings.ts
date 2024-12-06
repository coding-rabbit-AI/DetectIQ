import { useQuery } from '@tanstack/react-query';
import { settingsApi } from '@/api/client';

export function useSettings() {
  return useQuery({
    queryKey: ['app-config'],
    queryFn: () => settingsApi.getSettings(),
    staleTime: 30000,  // Cache for 30 seconds
    retry: 1
  });
} 