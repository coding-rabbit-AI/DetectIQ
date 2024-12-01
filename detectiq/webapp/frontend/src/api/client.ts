import axios from 'axios';
import { Rule, RuleFilters, PaginatedResponse, RuleType } from '@/types/rules';
import { Settings } from '@/types/settings';
import { RuleCreationResponse } from '@/types/api';
import { RuleCreationRequest } from '@/types/api';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  }
});

export const settingsApi = {
  getSettings: async () => {
    try {
      console.log('Fetching settings from:', '/api/settings/get_settings/');
      const response = await apiClient.get<Settings>('/settings/get_settings/');
      console.log('Settings response:', response);
      return response.data;
    } catch (error) {
      console.error('Error fetching settings:', error);
      if (axios.isAxiosError(error)) {
        console.error('Response data:', error.response?.data);
        console.error('Response status:', error.response?.status);
      }
      throw error;
    }
  }
};

export const rulesApi = {
  getRules: async (filters?: RuleFilters): Promise<PaginatedResponse<Rule>> => {
    const response = await apiClient.get<PaginatedResponse<Rule>>('/rules/', { 
      params: filters 
    });
    return response.data;
  },

  getRulesByType: async (type: RuleType): Promise<PaginatedResponse<Rule>> => {
    const response = await apiClient.get<PaginatedResponse<Rule>>(`/rules/${type}/`);
    return response.data;
  },

  searchRules: async (type: RuleType, query: string): Promise<PaginatedResponse<Rule>> => {
    const response = await apiClient.get<PaginatedResponse<Rule>>(`/rules/${type}/search/`, {
      params: { q: query }
    });
    return response.data;
  },

  createRule: async (formData: FormData): Promise<RuleCreationResponse> => {
    const response = await fetch('/api/rules/create_with_llm/', {
      method: 'POST',
      body: formData,
    });
    
    if (!response.ok) {
      throw new Error('Failed to create rule');
    }
    
    return response.json();
  },

  updateRule: async (ruleId: string, updates: Partial<Rule>): Promise<Rule> => {
    const response = await apiClient.patch<Rule>(`/rules/${ruleId}/`, updates);
    return response.data;
  },

  deleteRule: async (ruleId: string): Promise<void> => {
    await apiClient.delete(`/rules/${ruleId}/`);
  },

  updateSettings: async (settings: Partial<Settings>): Promise<Settings> => {
    const response = await apiClient.post<Settings>('/settings/update_settings/', settings);
    return response.data;
  },

  testIntegration: async (integration: string): Promise<{success: boolean; message: string}> => {
    const response = await apiClient.post<{success: boolean; message: string}>(
      '/settings/test_integration/', 
      { integration }
    );
    return response.data;
  },

  deployRule: async (ruleId: string, integration: string): Promise<{success: boolean; message: string}> => {
    const response = await apiClient.post<{success: boolean; message: string}>(
      `/rules/${ruleId}/deploy/`,
      { integration }
    );
    return response.data;
  },

  getRule: async (id: string): Promise<Rule> => {
    const response = await apiClient.get<Rule>(`/rules/${id}/`);
    return response.data;
  },
}; 