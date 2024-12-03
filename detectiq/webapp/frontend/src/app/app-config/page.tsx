'use client';

import { useState, useEffect } from 'react';
import { useMutation } from '@tanstack/react-query';
import { settingsApi } from '@/api/client';
import { Box, Button, Grid } from '@mui/material';
import { Save as SaveIcon } from '@mui/icons-material';
import { useSettings } from '@/hooks/useSettings';
import { Settings } from '@/types/settings';
import Notification from '@/components/common/Notification';
import PageLayout from '@/components/layout/PageLayout';
import DirectoriesSection from '@/components/app-config/DirectoriesSection';
import IntegrationsSection from '@/components/app-config/IntegrationsSection';
import OpenAISection from '@/components/app-config/OpenAISection';

export default function SettingsPage() {
  const { data: savedSettings, isLoading } = useSettings();
  const [settings, setSettings] = useState<Settings>({
    openai_api_key: '',
    rule_directories: {
      sigma: '',
      yara: '',
      snort: '',
    },
    vector_store_directories: {
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

  const [notification, setNotification] = useState<{
    message: string;
    type: 'success' | 'error';
    open: boolean;
  }>({
    message: '',
    type: 'success',
    open: false,
  });

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
        message: `Failed to save settings: ${error.message}`,
        type: 'error',
        open: true,
      });
    },
  });

  useEffect(() => {
    if (savedSettings) {
      setSettings(savedSettings);
    }
  }, [savedSettings]);

  const handleSave = async () => {
    try {
      await updateMutation.mutateAsync(settings);
    } catch (error) {
      console.error('Error saving settings:', error);
    }
  };

  return (
    <PageLayout title="Settings">
      <Box sx={{ p: 3 }}>
        <Grid container spacing={3}>
          {/* OpenAI Settings */}
          <Grid item xs={12}>
            <OpenAISection 
              apiKey={settings.openai_api_key}
              onChange={(value) => setSettings({ ...settings, openai_api_key: value })}
            />
          </Grid>

          {/* Directories */}
          <Grid item xs={12}>
            <DirectoriesSection
              ruleDirectories={settings.rule_directories}
              vectorStoreDirectories={settings.vector_store_directories}
              onRuleDirectoryChange={(type, value) => 
                setSettings({
                  ...settings,
                  rule_directories: { ...settings.rule_directories, [type]: value }
                })
              }
              onVectorStoreDirectoryChange={(type, value) =>
                setSettings({
                  ...settings,
                  vector_store_directories: { ...settings.vector_store_directories, [type]: value }
                })
              }
            />
          </Grid>

          {/* Integrations */}
          <Grid item xs={12}>
            <IntegrationsSection
              integrations={settings.integrations}
              onIntegrationChange={(integration, field, value) =>
                setSettings({
                  ...settings,
                  integrations: {
                    ...settings.integrations,
                    [integration as keyof typeof settings.integrations]: {
                      ...settings.integrations[integration as keyof typeof settings.integrations],
                      [field]: value,
                    },
                  },
                })
              }
            />
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

      <Notification
        open={notification.open}
        message={notification.message}
        type={notification.type}
        onClose={() => setNotification({ ...notification, open: false })}
      />
    </PageLayout>
  );
} 