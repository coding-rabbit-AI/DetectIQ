'use client';

import { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Divider,
  Alert,
  Grid,
  Switch,
  FormControlLabel,
  CircularProgress,
} from '@mui/material';
import { useQuery, useMutation } from '@tanstack/react-query';
import { rulesApi, settingsApi } from '@/api/client';
import { Settings, IntegrationCredentials } from '@/types/settings';
import Notification from '@/components/common/Notification';
import PageLayout from '@/components/layout/PageLayout';

interface TestResult {
  success: boolean;
  message: string;
}

interface TestResults {
  [key: string]: TestResult | null;
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

  const handleClose = () => {
    setNotification({ ...notification, open: false });
  };

  const updateMutation = useMutation({
    mutationFn: (newSettings: Settings) => rulesApi.updateSettings(newSettings),
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
    mutationFn: (integration: string) => rulesApi.testIntegration(integration),
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
    }
  });

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

  const handleSave = async () => {
    try {
      const settingsToUpdate = JSON.parse(JSON.stringify(settings));
      
      // Filter out masked passwords for all integrations
      Object.keys(settingsToUpdate.integrations).forEach(integration => {
        const integrationSettings = settingsToUpdate.integrations[integration];
        if (integrationSettings.password?.match(/^\*+$/)) {
          delete integrationSettings.password;
        }
        if (integrationSettings.api_key?.match(/^\*+$/)) {
          delete integrationSettings.api_key;
        }
        if (integrationSettings.client_secret?.match(/^\*+$/)) {
          delete integrationSettings.client_secret;
        }
      });

      await updateMutation.mutateAsync(settingsToUpdate);
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  };

  const handleTestIntegration = async (integration: string) => {
    try {
      // Create a copy of settings to modify
      const settingsToUpdate = JSON.parse(JSON.stringify(settings));
      
      // Remove masked passwords before saving
      if (settingsToUpdate.integrations[integration]) {
        const integrationSettings = settingsToUpdate.integrations[integration];
        // Check if password is all asterisks
        if (integrationSettings.password?.match(/^\*+$/)) {
          delete integrationSettings.password;
        }
        // Do the same for other sensitive fields if needed
        if (integrationSettings.api_key?.match(/^\*+$/)) {
          delete integrationSettings.api_key;
        }
        if (integrationSettings.client_secret?.match(/^\*+$/)) {
          delete integrationSettings.client_secret;
        }
      }

      // Save filtered settings then test connection
      await updateMutation.mutateAsync(settingsToUpdate);
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
      <Box sx={{ maxWidth: 'lg', mx: 'auto' }}>
        <Grid container spacing={3}>
          {/* API Keys */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  API Keys
                </Typography>
                <TextField
                  label="OpenAI API Key"
                  type="password"
                  value={settings.openai_api_key}
                  onChange={(e) =>
                    setSettings({ ...settings, openai_api_key: e.target.value })
                  }
                  fullWidth
                  margin="normal"
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Rule Directories */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
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
                      />
                    </Grid>
                  ))}
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Integrations */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Integrations
                </Typography>
                {Object.entries(settings.integrations).map(([name, config]) => (
                  <Box key={name} sx={{ mb: 3 }}>
                    <Typography variant="subtitle1" sx={{ mb: 2 }}>
                      {name.toUpperCase()}
                    </Typography>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={config.enabled}
                          onChange={(e) =>
                            setSettings({
                              ...settings,
                              integrations: {
                                ...settings.integrations,
                                [name]: {
                                  ...config,
                                  enabled: e.target.checked,
                                },
                              },
                            })
                          }
                        />
                      }
                      label="Enabled"
                    />
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <TextField
                          label="Hostname"
                          value={config.hostname}
                          onChange={(e) =>
                            handleUpdateIntegrationSetting(name, 'hostname', e.target.value)
                          }
                          fullWidth
                        />
                      </Grid>
                      
                      {/* Splunk specific fields */}
                      {name === 'splunk' && (
                        <>
                          <Grid item xs={12} md={6}>
                            <TextField
                              label="Username"
                              value={config.username || ''}
                              onChange={(e) =>
                                handleUpdateIntegrationSetting(name, 'username', e.target.value)
                              }
                              fullWidth
                              required
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
                              required
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              label="App (Optional)"
                              value={config.app || ''}
                              onChange={(e) =>
                                handleUpdateIntegrationSetting(name, 'app', e.target.value)
                              }
                              fullWidth
                              helperText="Splunk app context if needed"
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              label="Owner (Optional)"
                              value={config.owner || ''}
                              onChange={(e) =>
                                handleUpdateIntegrationSetting(name, 'owner', e.target.value)
                              }
                              fullWidth
                              helperText="Splunk owner context if needed"
                            />
                          </Grid>
                        </>
                      )}

                      {/* Elastic specific fields */}
                      {name === 'elastic' && (
                        <>
                          <Grid item xs={12}>
                            <TextField
                              label="Cloud ID"
                              value={config.cloud_id || ''}
                              onChange={(e) =>
                                handleUpdateIntegrationSetting(name, 'cloud_id', e.target.value)
                              }
                              fullWidth
                            />
                          </Grid>
                          <Grid item xs={12}>
                            <TextField
                              label="API Key"
                              type="password"
                              value={config.api_key || ''}
                              onChange={(e) =>
                                handleUpdateIntegrationSetting(name, 'api_key', e.target.value)
                              }
                              fullWidth
                            />
                          </Grid>
                        </>
                      )}

                      {/* Microsoft XDR specific fields */}
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
                            />
                          </Grid>
                          <Grid item xs={12}>
                            <TextField
                              label="Client Secret"
                              type="password"
                              value={config.client_secret || ''}
                              onChange={(e) =>
                                handleUpdateIntegrationSetting(name, 'client_secret', e.target.value)
                              }
                              fullWidth
                            />
                          </Grid>
                        </>
                      )}

                      {/* Common fields for all integrations */}
                      <Grid item xs={12}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={config.verify_ssl}
                              onChange={(e) =>
                                handleUpdateIntegrationSetting(name, 'verify_ssl', e.target.checked)
                              }
                            />
                          }
                          label="Verify SSL"
                        />
                      </Grid>
                    </Grid>
                    <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                      <Button
                        variant="outlined"
                        onClick={() => handleTestIntegration(name)}
                        disabled={!config.enabled || testIntegrationMutation.isPending}
                      >
                        Test Connection
                      </Button>
                    </Box>
                    {testResults[name] && (
                      <Alert 
                        severity={testResults[name]?.success ? 'success' : 'error'}
                        sx={{ mt: 2 }}
                      >
                        {testResults[name]?.message}
                      </Alert>
                    )}
                    <Divider sx={{ my: 2 }} />
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
            onClick={handleSave}
            disabled={updateMutation.isPending}
            sx={{ bgcolor: 'primary.main' }}
          >
            {updateMutation.isPending ? 'Saving...' : 'Save Settings'}
          </Button>
        </Box>

        <Notification
          open={notification.open}
          message={notification.message}
          severity={notification.type}
          onClose={handleClose}
        />
      </Box>
    </PageLayout>
  );
} 