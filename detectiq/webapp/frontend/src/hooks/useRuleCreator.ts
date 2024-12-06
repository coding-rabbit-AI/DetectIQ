import { useMutation } from '@tanstack/react-query';
import { ruleCreatorApi } from '@/api/client';
import { RuleCreationResponse } from '@/types/api';

export function useRuleCreator() {
  return useMutation({
    mutationFn: (formData: FormData) => ruleCreatorApi.createRule(formData),
  });
}