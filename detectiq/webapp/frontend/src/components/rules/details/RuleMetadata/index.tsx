import { Box, Typography, Divider, Card, CardContent } from '@mui/material';
import MITREATTACKInfo from '../../mitre/MITREATTACKInfo';
import { Rule } from '@/types/rules';

interface RuleMetadataProps {
  rule: Rule;
}

export default function RuleMetadata({ rule }: RuleMetadataProps) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {rule.type === 'sigma' && rule.metadata?.mitre_attack && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              MITRE ATT&CK
            </Typography>
            <MITREATTACKInfo data={rule.metadata.mitre_attack} />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Metadata
          </Typography>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {rule.metadata && Object.entries(rule.metadata)
              .filter(([key]) => key !== 'mitre_attack')
              .map(([key, value]) => (
                <Box key={key}>
                  <Typography variant="subtitle2" color="text.secondary">
                    {key.replace(/_/g, ' ').toUpperCase()}
                  </Typography>
                  <Typography variant="body2">
                    {typeof value === 'object' 
                      ? JSON.stringify(value, null, 2)
                      : value.toString()
                    }
                  </Typography>
                  <Divider sx={{ my: 1 }} />
                </Box>
              ))
            }
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
} 