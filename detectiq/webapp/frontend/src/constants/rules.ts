import { RuleSeverity } from "@/types/rules";

// Constants and mappings
export const RULE_TYPES = {
  SIGMA: 'sigma',
  YARA: 'yara',
  SNORT: 'snort'
} as const;

export const AVAILABLE_SOURCES = ['DetectIQ', 'SigmaHQ', 'YARA-Forge', 'Snort3 Community'] as const;

export const RULE_TYPE_LABELS = {
  [RULE_TYPES.SIGMA]: 'Sigma Rule',
  [RULE_TYPES.YARA]: 'YARA Rule',
  [RULE_TYPES.SNORT]: 'Snort Rule'
} as const;

export const RULE_SOURCES = {
  [RULE_TYPES.SIGMA]: (integration?: string) => integration === 'llm' ? 'DetectIQ' : 'SigmaHQ',
  [RULE_TYPES.YARA]: (integration?: string) => integration === 'llm' ? 'DetectIQ' : 'YARA-Forge',
  [RULE_TYPES.SNORT]: (integration?: string) => integration === 'llm' ? 'DetectIQ' : 'Snort3 Community'
} as const;

export const INTEGRATIONS = {
  SPLUNK: 'splunk',
  ELASTIC: 'elastic',
  MICROSOFT_XDR: 'microsoft_xdr'
} as const;

export const INTEGRATION_LABELS = {
  [INTEGRATIONS.SPLUNK]: 'Splunk',
  [INTEGRATIONS.ELASTIC]: 'Elastic',
  [INTEGRATIONS.MICROSOFT_XDR]: 'Microsoft XDR'
} as const;


export const SEVERITY_STYLES: Record<RuleSeverity, {
  backgroundColor: string;
  color: string;
}> = {
  'critical': {
    backgroundColor: '#dc3545',
    color: '#fff'
  },
  'high': {
    backgroundColor: '#fd7e14',
    color: '#fff'
  },
  'medium': {
    backgroundColor: '#ffc107',
    color: '#000'
  },
  'low': {
    backgroundColor: '#17a2b8',
    color: '#fff'
  },
  'informational': {
    backgroundColor: '#6c757d',
    color: '#fff'
  }
} as const;

export const SEVERITY_OPTIONS: RuleSeverity[] = [
  'informational',
  'low', 
  'medium', 
  'high', 
  'critical'
];

export const ruleTypeMap = {
  'sigma': 'Sigma Rule',
  'yara': 'YARA Rule',
  'snort': 'Snort Rule'
} as const;

export const severityOptions = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'informational', label: 'Informational' }
] as const;

export const ruleSourceMap = {
  'sigma': (integration?: string) => integration === 'llm' ? 'DetectIQ' : 'SigmaHQ',
  'yara': (integration?: string) => integration === 'llm' ? 'DetectIQ' : 'YARA-Forge',
  'snort': (integration?: string) => integration === 'llm' ? 'DetectIQ' : 'Snort3 Community'
} as const;

export const severityColorMap = {
  'critical': 'error',
  'high': 'error',
  'medium': 'warning',
  'low': 'info',
  'informational': 'default'
} as const;

// You can also keep SEVERITY_COLORS for backward compatibility
export const SEVERITY_COLORS = severityColorMap;