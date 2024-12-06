import { RuleType, RuleSeverity } from './rules';

export interface RuleCreationRequest {
  type: RuleType;
  description: string;
  file?: File;
}

export interface RuleCreationResponse {
  id: string;
  title: string;
  content: string;
  type: string;
  severity: string;
  description: string;
  agent_output: string;
}

export interface FileAnalysisResponse {
  fileName: string;
  analysis: Record<string, any>;
} 