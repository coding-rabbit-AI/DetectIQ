import { FileAnalysisResponse, RuleCreationRequest, RuleCreationResponse } from '@/types/api';
import { Rule } from '@/types/rules';

export const rulesApi = {
  async analyzeFile(formData: FormData): Promise<FileAnalysisResponse> {
    const response = await fetch('/rules/analyze-file/', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to analyze file');
    }

    return await response.json();
  },

  async createRule(data: RuleCreationRequest): Promise<RuleCreationResponse> {
    const response = await fetch('/rules/create-rule/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to create rule');
    }

    return await response.json();
  },

  async getRule(id: string): Promise<Rule> {
    const response = await fetch(`/rules/${id}/`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to fetch rule');
    }

    return await response.json();
  },
}; 