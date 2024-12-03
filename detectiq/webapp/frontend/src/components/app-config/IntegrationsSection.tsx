import { useState } from 'react';
import { 
  Card, 
  CardContent, 
  Typography, 
  Box, 
  Grid, 
  TextField, 
  Switch, 
  FormControlLabel, 
  IconButton, 
  Tooltip 
} from '@mui/material';
import { 
  Science as TestIcon,
  Construction as WorkInProgressIcon 
} from '@mui/icons-material';
import { IntegrationCredentials } from '@/types/settings';

interface IntegrationsSectionProps {
  integrations: {
    [key: string]: IntegrationCredentials;
  };
  onIntegrationChange: (integration: string, field: string, value: any) => void;
}

const IMPLEMENTED_INTEGRATIONS = ['splunk'];

export default function IntegrationsSection({ 
  integrations, 
  onIntegrationChange 
}: IntegrationsSectionProps) {
  const [testResults, setTestResults] = useState<{
    [key: string]: { success: boolean; message: string };
  }>({});

  const handleTestIntegration = async (integration: string) => {
    try {
      const response = await fetch('/api/app-config/test_integration/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ integration }),
      });
      const result = await response.json();
      setTestResults({ ...testResults, [integration]: result });
    } catch (error) {
      setTestResults({
        ...testResults,
        [integration]: { success: false, message: 'Test failed' },
      });
    }
  };

  return (
    <Card elevation={2}>
      <CardContent>
        <Typography variant="h6" gutterBottom color="primary">
          Integrations
        </Typography>
        {Object.entries(integrations).map(([name, config]) => (
          <Box key={name} sx={{ mb: 4, position: 'relative' }}>
            <Card 
              elevation={1}
              sx={{
                opacity: IMPLEMENTED_INTEGRATIONS.includes(name) ? 1 : 0.6,
                position: 'relative'
              }}
            >
              {!IMPLEMENTED_INTEGRATIONS.includes(name) && (
                <Box
                  sx={{
                    position: 'absolute',
                    top: 16,
                    left: 0,
                    right: 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 1,
                  }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                      bgcolor: 'background.paper',
                      px: 2,
                      py: 1,
                      borderRadius: 1,
                      boxShadow: 1,
                    }}
                  >
                    <WorkInProgressIcon color="action" />
                    <Typography variant="subtitle1" color="text.secondary">
                      Coming Soon
                    </Typography>
                  </Box>
                </Box>
              )}
              <CardContent>
                <Box sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  mb: 3,
                  pb: 2,
                  borderBottom: '1px solid',
                  borderColor: 'divider'
                }}>
                  <Box sx={{ 
                    width: 40, 
                    height: 40, 
                    mr: 2,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <img
                      src={`/icons/${name}.svg`}
                      alt={`${name} logo`}
                      style={{
                        width: '100%',
                        height: '100%',
                        objectFit: 'contain'
                      }}
                    />
                  </Box>
                  <Typography variant="h6" sx={{ flexGrow: 1, textTransform: 'capitalize' }}>
                    {name.replace('_', ' ')}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <Tooltip title={IMPLEMENTED_INTEGRATIONS.includes(name) ? "Test Connection" : "Coming Soon"}>
                      <span>
                        <IconButton
                          onClick={() => handleTestIntegration(name)}
                          disabled={!IMPLEMENTED_INTEGRATIONS.includes(name)}
                          color={testResults[name]?.success ? 'success' : testResults[name]?.message ? 'error' : 'default'}
                        >
                          <TestIcon />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={config.enabled}
                          onChange={(e) => onIntegrationChange(name, 'enabled', e.target.checked)}
                          disabled={!IMPLEMENTED_INTEGRATIONS.includes(name)}
                        />
                      }
                      label="Enable"
                    />
                  </Box>
                </Box>
                <IntegrationFields 
                  name={name} 
                  config={config} 
                  onChange={onIntegrationChange}
                  disabled={!IMPLEMENTED_INTEGRATIONS.includes(name)}
                />
              </CardContent>
            </Card>
          </Box>
        ))}
      </CardContent>
    </Card>
  );
}

function IntegrationFields({
  name,
  config,
  onChange,
  disabled
}: {
  name: string;
  config: IntegrationCredentials;
  onChange: (integration: string, field: string, value: any) => void;
  disabled: boolean;
}): JSX.Element {
  const fields: { [key: string]: string[] } = {
    splunk: ['hostname', 'username', 'password', 'app', 'owner'],
    elastic: ['hostname', 'cloud_id', 'api_key'],
    microsoft_xdr: ['hostname', 'tenant_id', 'client_id', 'client_secret'],
  };

  return (
    <Grid container spacing={2}>
      {fields[name]?.map((field) => (
        <Grid item xs={12} sm={6} key={field}>
          <TextField
            label={field.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
            value={config[field] || ''}
            onChange={(e) => onChange(name, field, e.target.value)}
            type={field.includes('password') || field.includes('secret') || field.includes('key') ? 'password' : 'text'}
            fullWidth
            disabled={disabled}
          />
        </Grid>
      ))}
    </Grid>
  );
} 