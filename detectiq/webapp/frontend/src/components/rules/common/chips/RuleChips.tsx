import { Box, Chip } from '@mui/material';
import { Rule, IntegrationType } from '@/types/rules';
import { 
  RULE_TYPE_LABELS, 
  RULE_SOURCES, 
  INTEGRATION_LABELS, 
  SEVERITY_COLORS, 
  SEVERITY_STYLES,
  INTEGRATIONS 
} from '@/constants/rules';

interface RuleChipsProps {
  rule: Rule;
  size?: 'small' | 'medium';
}

export default function RuleChips({ rule, size = 'small' }: RuleChipsProps) {
  // Helper function to safely get integration label
  const getIntegrationLabel = (integration: string) => {
    const key = Object.keys(INTEGRATIONS).find(
      k => INTEGRATIONS[k as keyof typeof INTEGRATIONS] === integration
    );
    return key ? INTEGRATION_LABELS[INTEGRATIONS[key as keyof typeof INTEGRATIONS] as IntegrationType] : integration;
  };

  return (
    <Box sx={{ 
      display: 'flex', 
      gap: 1, 
      flexWrap: 'wrap',
      width: '100%',
      maxWidth: '100%',
      overflow: 'hidden'
    }}>
      <Chip 
        label={RULE_TYPE_LABELS[rule.type] || rule.type}
        size={size}
        color="primary"
        variant="outlined"
      />
      <Chip 
        label={RULE_SOURCES[rule.type](rule.integration) || 'Custom'}
        size={size}
        color="secondary"
        variant="outlined"
      />
      <Chip 
        label={rule.severity}
        size={size}
        color={SEVERITY_COLORS[rule.severity]}
        sx={SEVERITY_STYLES[rule.severity]}
      />
      {rule.integration && (
        <Chip 
          label={getIntegrationLabel(rule.integration)}
          size={size}
          variant="outlined"
        />
      )}
    </Box>
  );
} 