import { useQuery, useQueryClient } from '@tanstack/react-query';
import { PaginatedResponse, Rule, RuleFilters } from '@/types/rules';

export function useRules(filters: RuleFilters, page: number) {
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<PaginatedResponse<Rule>, Error>({
    queryKey: ['rules', filters, page],
    queryFn: async () => {
      const queryParams = new URLSearchParams();
      queryParams.append('page', page.toString());
      queryParams.append('page_size', '10');
      
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          if (Array.isArray(value)) {
            value.forEach(v => {
              if (v !== null && v !== undefined) {
                queryParams.append(key, v.toString());
              }
            });
          } else {
            queryParams.append(key, value.toString());
          }
        }
      });
      
      const response = await fetch(`/rules/?${queryParams.toString()}`);
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return await response.json();
    },
    staleTime: 30000,
    retry: 1
  });

  return {
    data,
    isLoading,
    error,
    invalidateRules: () => queryClient.invalidateQueries({ queryKey: ['rules'] })
  };
}