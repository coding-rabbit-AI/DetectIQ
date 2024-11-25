import { create } from 'zustand';
import { DetectionRule, RuleFilters } from '@/types/rules';

interface RuleState {
  rules: DetectionRule[];
  filters: RuleFilters;
  selectedRule: DetectionRule | null;
  setRules: (rules: DetectionRule[]) => void;
  setFilters: (filters: RuleFilters) => void;
  setSelectedRule: (rule: DetectionRule | null) => void;
}

export const useRuleStore = create<RuleState>((set) => ({
  rules: [],
  filters: { enabled: true },
  selectedRule: null,
  setRules: (rules) => set({ rules }),
  setFilters: (filters) => set({ filters }),
  setSelectedRule: (rule) => set({ selectedRule: rule }),
})); 