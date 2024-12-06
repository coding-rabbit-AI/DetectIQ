import { AVAILABLE_SOURCES } from "@/constants/rules";

export type RuleType = 'sigma' | 'yara' | 'snort';
export type RuleSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type IntegrationType = 'splunk' | 'elastic' | 'microsoft_xdr';

export interface Rule {
  id: string;
  title: string;
  content: string;
  type: RuleType;
  severity: RuleSeverity;
  integration?: string;
  metadata?: Record<string, any>;
  description?: string;
  is_enabled: boolean;
  tags?: string[];
  source?: string;
  package_type?: string;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
}

export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface RuleFilters {
  integration?: IntegrationType;
  type?: RuleType;
  severity?: RuleSeverity;
  mitreTactic?: string[];
  enabled?: boolean;
  page?: number;
  page_size?: number;
  search?: string;
  source?: string;
} 