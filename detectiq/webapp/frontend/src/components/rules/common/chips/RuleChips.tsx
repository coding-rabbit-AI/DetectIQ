import { Box, Chip, Tooltip } from '@mui/material';
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
  showMitre?: boolean; // Optional prop to control MITRE chips visibility
}

export default function RuleChips({ rule, size = 'small', showMitre = true }: RuleChipsProps) {
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
        label={rule.source || 'manual'}
        size={size}
        color="secondary"
        variant="outlined"
      />
      <Chip 
        label={rule.package_type || 'manual'}
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
      {rule.integration && rule.integration !== 'manual' && (
        <Chip 
          label={getIntegrationLabel(rule.integration)}
          size={size}
          variant="outlined"
        />
      )}
      
      {/* MITRE Tactics Chips */}
      {showMitre && rule.mitre_tactics && rule.mitre_tactics.length > 0 && (
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
          {rule.mitre_tactics.slice(0, 2).map((tactic) => (
            <Tooltip key={tactic} title={`MITRE Tactic: ${tactic}`}>
              <Chip
                label={tactic.split(' ').map(word => {
                  let abbrev = word.slice(0, 3);
                  // If the third letter is a vowel, include up to the next consonant
                  if (/[aeiou]$/i.test(abbrev)) {
                    for (let i = 3; i < word.length; i++) {
                      abbrev = word.slice(0, i + 1);
                      if (!/[aeiou]$/i.test(abbrev)) {
                        break;
                      }
                    }
                  }
                  return `${abbrev}.`;
                }).join(' ')}
                size={size}
                color="info"
                variant="outlined"
                sx={{ borderStyle: 'dashed' }}
              />
            </Tooltip>
          ))}
          {rule.mitre_tactics.length > 2 && (
            <Tooltip title={`${rule.mitre_tactics.length - 2} more tactics`}>
              <Chip
                label={`+${rule.mitre_tactics.length - 2}`}
                size={size}
                color="info"
                variant="outlined"
                sx={{ borderStyle: 'dashed' }}
              />
            </Tooltip>
          )}
        </Box>
      )}

      {/* MITRE Techniques Chips */}
      {showMitre && rule.mitre_techniques && rule.mitre_techniques.length > 0 && (
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
          {rule.mitre_techniques.slice(0, 2).map((technique) => (
            <Tooltip key={technique} title={`MITRE Technique: ${technique}`}>
              <Chip
                label={technique}
                size={size}
                color="info"
                variant="outlined"
                sx={{ borderStyle: 'dashed' }}
              />
            </Tooltip>
          ))}
          {rule.mitre_techniques.length > 2 && (
            <Tooltip title={`${rule.mitre_techniques.length - 2} more techniques`}>
              <Chip
                label={`+${rule.mitre_techniques.length - 2}`}
                size={size}
                color="info"
                variant="outlined"
                sx={{ borderStyle: 'dashed' }}
              />
            </Tooltip>
          )}
        </Box>
      )}
    </Box>
  );
} 