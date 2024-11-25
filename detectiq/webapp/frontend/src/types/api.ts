import { RuleType, RuleSeverity } from './rules';

export interface RuleCreationRequest {
  type: RuleType;
  description: string;
  file?: File;
}

export interface RuleCreationResponse {
  id: string;
  content: string;
  title: string;
  severity: RuleSeverity;
  agent_output?: string;
}

export interface FileAnalysisResponse {
  fileName: string;
  analysis: Record<string, any>;
} 