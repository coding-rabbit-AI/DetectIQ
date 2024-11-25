import { useQuery } from '@tanstack/react-query';
import { settingsApi } from '@/api/client';

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.getSettings(),
  });
} 