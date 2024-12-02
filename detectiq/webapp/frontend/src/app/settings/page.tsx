'use client';

import { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Grid,
  Switch,
  FormControlLabel,
  CircularProgress,
  IconButton,
  Tooltip,
} from '@mui/material';
import { useQuery, useMutation } from '@tanstack/react-query';
import { settingsApi } from '@/api/client';
import { Settings, IntegrationCredentials } from '@/types/settings';
import Notification from '@/components/common/Notification';
import PageLayout from '@/components/layout/PageLayout';
import { Science as TestIcon, Save as SaveIcon } from '@mui/icons-material';

interface TestResults {
  [key: string]: {
    success: boolean;
    message: string;
  };
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings>({
    openai_api_key: '',
    rule_directories: {
      sigma: '',
      yara: '',
      snort: '',
    },
    integrations: {
      splunk: {
        hostname: '',
        username: '',
        password: '',
        app: '',
        owner: '',
        verify_ssl: true,
        enabled: false,
      },
      elastic: {
        hostname: '',
        cloud_id: '',
        api_key: '',
        verify_ssl: true,
        enabled: false,
      },
      microsoft_xdr: {
        hostname: '',
        tenant_id: '',
        client_id: '',
        client_secret: '',
        verify_ssl: true,
        enabled: false,
      },
    },
  });

  const [testResults, setTestResults] = useState<TestResults>({});

  const [notification, setNotification] = useState<{
    message: string;
    type: 'success' | 'error';
    open: boolean;
  }>({
    message: '',
    type: 'success',
    open: false,
  });

  const { data: savedSettings, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: settingsApi.getSettings,
  });

  useEffect(() => {
    if (savedSettings) {
      setSettings(savedSettings);
    }
  }, [savedSettings]);

  const handleUpdateIntegrationSetting = (
    integration: string,
    field: keyof IntegrationCredentials,
    value: any
  ) => {
    setSettings({
      ...settings,
      integrations: {
        ...settings.integrations,
        [integration]: {
          ...settings.integrations[integration as keyof typeof settings.integrations],
          [field]: value,
        },
      },
    });
  };

  const handleClose = () => {
    setNotification({ ...notification, open: false });
  };

  const updateMutation = useMutation({
    mutationFn: settingsApi.updateSettings,
    onSuccess: () => {
      setNotification({
        message: 'Settings saved successfully',
        type: 'success',
        open: true,
      });
    },
    onError: (error) => {
      setNotification({
        message: `Failed to save settings: ${error}`,
        type: 'error',
        open: true,
      });
    },
  });

  const testIntegrationMutation = useMutation({
    mutationFn: settingsApi.testIntegration,
    onSuccess: (data, integration) => {
      setTestResults(prev => ({
        ...prev,
        [integration]: {
          success: data.success,
          message: data.message || 'Connection successful'
        }
      }));
      setNotification({
        message: data.success ? 'Connection test successful' : 'Connection test failed',
        type: data.success ? 'success' : 'error',
        open: true,
      });
    },
    onError: (error, integration) => {
      setTestResults(prev => ({
        ...prev,
        [integration]: {
          success: false,
          message: 'Failed to test connection'
        }
      }));
      setNotification({
        message: `Failed to test connection: ${error}`,
        type: 'error',
        open: true,
      });
    },
  });

  const handleSave = async () => {
    try {
      await updateMutation.mutateAsync(settings);
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  };

  const handleTestIntegration = async (integration: string) => {
    try {
      await testIntegrationMutation.mutateAsync(integration);
    } catch (error) {
      console.error(`Failed to test ${integration} integration:`, error);
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <PageLayout title="Settings">
      <Box sx={{ maxWidth: 'lg', mx: 'auto', p: 3 }}>
        <Grid container spacing={3}>
          {/* API Keys */}
          <Grid item xs={12}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  API Keys
                </Typography>
                <TextField
                  label="OpenAI API Key"
                  type="password"
                  value={settings.openai_api_key}
                  onChange={(e) => setSettings({ ...settings, openai_api_key: e.target.value })}
                  fullWidth
                  margin="normal"
                  variant="outlined"
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Rule Directories */}
          <Grid item xs={12}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  Rule Directories
                </Typography>
                <Grid container spacing={2}>
                  {Object.entries(settings.rule_directories).map(([type, path]) => (
                    <Grid item xs={12} key={type}>
                      <TextField
                        label={`${type.toUpperCase()} Rules Directory`}
                        value={path}
                        onChange={(e) =>
                          setSettings({
                            ...settings,
                            rule_directories: {
                              ...settings.rule_directories,
                              [type]: e.target.value,
                            },
                          })
                        }
                        fullWidth
                        variant="outlined"
                      />
                    </Grid>
                  ))}
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Integrations */}
          <Grid item xs={12}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  Integrations
                </Typography>
                {Object.entries(settings.integrations).map(([name, config]) => (
                  <Box key={name} sx={{ mb: 4 }}>
                    <Card elevation={2}>
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
                            <Tooltip title="Test Connection">
                              <IconButton
                                onClick={() => handleTestIntegration(name)}
                                disabled={testIntegrationMutation.isPending}
                                color={testResults[name]?.success ? 'success' : testResults[name]?.message ? 'error' : 'default'}
                              >
                                <TestIcon />
                              </IconButton>
                            </Tooltip>
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={config.enabled}
                                  onChange={(e) => handleUpdateIntegrationSetting(name, 'enabled', e.target.checked)}
                                  color="primary"
                                />
                              }
                              label="Enable"
                            />
                          </Box>
                        </Box>
                        <Grid container spacing={2}>
                          {/* Integration specific fields */}
                          {name === 'splunk' && (
                            <>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="Hostname"
                                  value={config.hostname}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'hostname', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="Username"
                                  value={config.username || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'username', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="Password"
                                  type="password"
                                  value={config.password || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'password', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="App"
                                  value={config.app || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'app', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                            </>
                          )}
                          
                          {/* Similar blocks for elastic and microsoft_xdr */}
                          {name === 'elastic' && (
                            <>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="Cloud ID"
                                  value={config.cloud_id || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'cloud_id', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="API Key"
                                  type="password"
                                  value={config.api_key || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'api_key', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                            </>
                          )}

                          {name === 'microsoft_xdr' && (
                            <>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="Tenant ID"
                                  value={config.tenant_id || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'tenant_id', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="Client ID"
                                  value={config.client_id || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'client_id', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  label="Client Secret"
                                  type="password"
                                  value={config.client_secret || ''}
                                  onChange={(e) =>
                                    handleUpdateIntegrationSetting(name, 'client_secret', e.target.value)
                                  }
                                  fullWidth
                                  variant="outlined"
                                />
                              </Grid>
                            </>
                          )}
                        </Grid>
                      </CardContent>
                    </Card>
                  </Box>
                ))}
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Save Button */}
        <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
          <Button
            variant="contained"
            color="primary"
            onClick={handleSave}
            startIcon={<SaveIcon />}
            sx={{ minWidth: 120 }}
          >
            Save
          </Button>
        </Box>
      </Box>

      {/* Notification */}
      <Notification
        open={notification.open}
        message={notification.message}
        type={notification.type}
        onClose={handleClose}
      />
    </PageLayout>
  );
} 