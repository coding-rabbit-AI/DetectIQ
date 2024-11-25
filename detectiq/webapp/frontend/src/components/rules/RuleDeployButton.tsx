import React, { useState } from 'react';
import {
  Button,
  Menu,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  CircularProgress,
  Snackbar,
  Alert,
  Box
} from '@mui/material';
import { useSettings } from '@/hooks/useSettings';
import { rulesApi } from '@/api/client';
import { INTEGRATION_LABELS, INTEGRATIONS } from '@/constants/rules';
import { IntegrationConfig } from '@/types/settings';

interface RuleDeployButtonProps {
  ruleId: string | number;
  onSuccess?: (integration: string) => void;
}

export default function RuleDeployButton({ ruleId, onSuccess }: RuleDeployButtonProps) {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [deploying, setDeploying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const { data: settings } = useSettings();

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
    setError(null);
  };

  const handleSnackbarClose = () => {
    setSuccessMessage(null);
  };

  const getIntegrationLabel = (integration: string) => {
    const key = Object.keys(INTEGRATIONS).find(
      k => INTEGRATIONS[k as keyof typeof INTEGRATIONS] === integration
    );
    return key ? INTEGRATION_LABELS[INTEGRATIONS[key as keyof typeof INTEGRATIONS]] : integration;
  };

  const handleDeploy = async (integration: string) => {
    setDeploying(true);
    setError(null);
    
    try {
      const ruleIdString = ruleId.toString();
      const result = await rulesApi.deployRule(ruleIdString, integration);
      console.log('Deploy result:', result);
      
      if ('success' in result && result.success) {
        onSuccess?.(integration);
        handleClose();
      } else {
        setError('message' in result ? result.message : 'Unknown error');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to deploy rule');
    } finally {
      setDeploying(false);
    }
  };

  // Get enabled integrations with proper type checking
  const enabledIntegrations = Object.entries(settings?.integrations || {} as Record<string, IntegrationConfig>)
    .filter((entry): entry is [string, IntegrationConfig] => {
      const [_, config] = entry;
      return Boolean(config && typeof config === 'object' && 'enabled' in config && config.enabled === true);
    })
    .map(([key]) => key);

  // Only return null if settings are loaded and there are no enabled integrations
  if (settings && enabledIntegrations.length === 0) {
    return null;
  }

  return (
    <Box sx={{ display: 'inline-block', position: 'relative' }}>
      <Button
        variant="outlined"
        size="small"
        disabled={deploying}
        sx={{
          minWidth: 100,
          position: 'relative',
          overflow: 'hidden',
          '&::after': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'linear-gradient(90deg, transparent, rgba(97, 84, 163, 0.2), transparent)',
            transform: 'translateX(-100%)',
            animation: deploying ? 'shimmer 1.5s infinite' : 'none',
          },
          '@keyframes shimmer': {
            '100%': {
              transform: 'translateX(100%)',
            },
          }
        }}
        onClick={handleClick}
      >
        {deploying ? <CircularProgress size={24} /> : 'Deploy'}
      </Button>
      
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        onClick={(e) => e.stopPropagation()}
      >
        {enabledIntegrations.map((integration) => (
          <MenuItem 
            key={integration}
            onClick={() => handleDeploy(integration)}
          >
            {getIntegrationLabel(integration)}
          </MenuItem>
        ))}
      </Menu>

      <Dialog 
        open={Boolean(error)} 
        onClose={handleClose}
        onClick={(e) => e.stopPropagation()}
      >
        <DialogTitle>Deployment Error</DialogTitle>
        <DialogContent>{error}</DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        key={successMessage}
        open={Boolean(successMessage)}
        autoHideDuration={6000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        sx={{ position: 'fixed', zIndex: 9999 }}
      >
        <Alert 
          onClose={handleSnackbarClose} 
          severity="success"
          variant="filled"
          elevation={6}
          sx={{ 
            width: '100%',
            minWidth: '300px'
          }}
        >
          {successMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
} 