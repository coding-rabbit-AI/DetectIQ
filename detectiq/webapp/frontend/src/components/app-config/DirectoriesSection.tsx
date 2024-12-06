import { Card, CardContent, Typography, Box, Select, MenuItem, Chip, Tabs, Tab, TextField, FormControl, InputLabel, Button } from '@mui/material';
import { Update as UpdateIcon, Refresh as RefreshIcon, CheckCircle as CheckCircleIcon, Warning as WarningIcon } from '@mui/icons-material';
import { useState, useEffect } from 'react';
import { settingsApi } from '@/api/client';
import Notification from '@/components/common/Notification';

const SIGMA_PACKAGES = [
  { 
    value: 'core', 
    label: 'Core', 
    recommended: true, 
    description: 'Stable, high-confidence rules for critical threats' 
  },
  { 
    value: 'core+', 
    label: 'Core+', 
    recommended: false, 
    description: 'Extended ruleset including medium-confidence detections' 
  },
  { 
    value: 'core++', 
    label: 'Core++', 
    recommended: false, 
    description: 'Complete core ruleset including experimental rules' 
  },
  { 
    value: 'emerging_threats', 
    label: 'Emerging Threats', 
    recommended: false, 
    description: 'Latest threat detection rules from emerging threats' 
  },
  { 
    value: 'all', 
    label: 'All Rules',
    recommended: false,  
    description: 'All rules including core and emerging threats' 
  },
] as const;

const YARA_PACKAGES = [
  { 
    value: 'core', 
    label: 'Core', 
    recommended: true, 
    description: 'High accuracy rules with low false positives, optimized for performance' 
  },
  { 
    value: 'extended', 
    label: 'Extended', 
    recommended: false, 
    description: 'Expanded threat hunting rules with balanced coverage' 
  },
  { 
    value: 'full', 
    label: 'Full', 
    recommended: false, 
    description: 'Complete ruleset for maximum threat detection coverage' 
  },
] as const;

interface DirectoriesSectionProps {
  sigmaPackageType: string;
  onSigmaPackageTypeChange: (value: string) => void;
  yaraPackageType: string;
  onYaraPackageTypeChange: (value: string) => void;
  ruleDirectories: { [key: string]: string };
  vectorStoreDirectories: { [key: string]: string };
  onRuleDirectoryChange: (type: string, value: string) => void;
  onVectorStoreDirectoryChange: (type: string, value: string) => void;
}

interface RulePackageStatus {
  current_version: string;
  latest_version: string;
  needs_update: boolean;
}

interface PackageStatuses {
  [key: string]: RulePackageStatus;
}

interface VectorStoreStatus {
  [key: string]: {
    exists: boolean;
  };
}

export default function DirectoriesSection({
  sigmaPackageType = 'core',
  onSigmaPackageTypeChange,
  yaraPackageType = 'core',
  onYaraPackageTypeChange,
  ruleDirectories,
  vectorStoreDirectories,
  onRuleDirectoryChange,
  onVectorStoreDirectoryChange,
}: DirectoriesSectionProps) {
  const [selectedTab, setSelectedTab] = useState(0);
  const [isUpdating, setIsUpdating] = useState(false);
  const [isRebuilding, setIsRebuilding] = useState(false);
  const [packageStatuses, setPackageStatuses] = useState<PackageStatuses>({});
  const [isCheckingUpdates, setIsCheckingUpdates] = useState(false);
  const [notification, setNotification] = useState<{
    message: string;
    type: 'success' | 'error';
    open: boolean;
  }>({ message: '', type: 'success', open: false });
  const [vectorStoreStatus, setVectorStoreStatus] = useState<VectorStoreStatus>({});

  useEffect(() => {
    checkRulePackages();
    checkVectorStores();
  }, []);

  const checkRulePackages = async () => {
    try {
      setIsCheckingUpdates(true);
      const response = await settingsApi.checkRulePackages();
      setPackageStatuses(response);
    } catch (error) {
      console.error('Error checking rule packages:', error);
    } finally {
      setIsCheckingUpdates(false);
    }
  };

  const checkVectorStores = async () => {
    try {
      const status = await settingsApi.checkVectorstores();
      setVectorStoreStatus(status);
    } catch (error) {
      console.error('Error checking vectorstores:', error);
    }
  };

  const handleUpdateRules = async (type: string, packageType?: string) => {
    setIsUpdating(true);
    try {
      await settingsApi.updateRulePackage(type, packageType);
      await checkRulePackages(); // Refresh status after update
      setNotification({
        message: `Successfully updated ${type} rules`,
        type: 'success',
        open: true,
      });
    } catch (error) {
      console.error('Error updating rules:', error);
      setNotification({
        message: `Failed to update ${type} rules`,
        type: 'error',
        open: true,
      });
    } finally {
      setIsUpdating(false);
    }
  };

  const handleRebuildVectorStore = async (type: string) => {
    setIsRebuilding(true);
    try {
      await settingsApi.createVectorstore(type);
      setNotification({
        message: `Successfully rebuilt ${type} vector store`,
        type: 'success',
        open: true,
      });
    } catch (error) {
      console.error(`Error rebuilding ${type} vector store:`, error);
      setNotification({
        message: `Failed to rebuild ${type} vector store`,
        type: 'error',
        open: true,
      });
    } finally {
      setIsRebuilding(false);
    }
  };

  const renderUpdateStatus = (type: string) => {
    const status = packageStatuses[type];
    if (!status || isCheckingUpdates) return null;

    return (
      <Box sx={{ mt: 1, mb: 2 }}>
        <Typography variant="body2" color="textSecondary">
          Current version: {status.current_version}
          {status.needs_update && (
            <>
              <br />
              Latest version: {status.latest_version}
              <Button
                size="small"
                variant="outlined"
                startIcon={<UpdateIcon />}
                onClick={() => handleUpdateRules(type, type === 'sigma' ? sigmaPackageType : yaraPackageType)}
                disabled={isUpdating}
                sx={{ ml: 2 }}
              >
                {isUpdating ? 'Updating...' : 'Update Available'}
              </Button>
            </>
          )}
        </Typography>
      </Box>
    );
  };

  const renderVectorStoreStatus = (type: string) => (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
      {vectorStoreStatus[type]?.exists ? (
        <Typography variant="caption" color="success.main" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <CheckCircleIcon fontSize="small" />
          Vector store initialized
        </Typography>
      ) : (
        <Typography variant="caption" color="warning.main" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <WarningIcon fontSize="small" />
          Vector store not initialized
        </Typography>
      )}
    </Box>
  );

  const renderActionButtons = (type: string, packageType?: string) => (
    <Box sx={{ mt: 3, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
      <Button
        variant="outlined"
        startIcon={<UpdateIcon />}
        onClick={() => handleUpdateRules(type, packageType)}
        disabled={isUpdating}
      >
        {isUpdating ? 'Updating Rules...' : 'Update Rules'}
      </Button>
      <Button
        variant="outlined"
        startIcon={<RefreshIcon />}
        onClick={() => handleRebuildVectorStore(type)}
        disabled={isRebuilding}
        color={vectorStoreStatus[type]?.exists ? 'primary' : 'warning'}
      >
        {isRebuilding ? 'Rebuilding...' : vectorStoreStatus[type]?.exists ? 'Rebuild Vector Store' : 'Create Vector Store'}
      </Button>
    </Box>
  );

  return (
    <>
      <Card elevation={2}>
        <CardContent>
          <Typography variant="h6" color="primary" gutterBottom>
            Rule Packages
          </Typography>

          <Tabs value={selectedTab} onChange={(e, newValue) => setSelectedTab(newValue)}>
            <Tab label="Sigma Settings" />
            <Tab label="YARA Settings" />
            <Tab label="Snort Settings" />
          </Tabs>

          {/* Sigma Settings Tab */}
          {selectedTab === 0 && (
            <Box sx={{ mt: 2 }}>
              <FormControl fullWidth sx={{ mb: 3 }}>
                <InputLabel>Sigma Package Type</InputLabel>
                <Select
                  value={sigmaPackageType}
                  label="Sigma Package Type"
                  onChange={(e) => onSigmaPackageTypeChange(e.target.value)}
                >
                  {SIGMA_PACKAGES.map((pkg) => (
                    <MenuItem key={pkg.value} value={pkg.value}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                        <Box>
                          {pkg.label}
                          <Typography variant="caption" color="textSecondary" display="block">
                            {pkg.description}
                          </Typography>
                        </Box>
                        {pkg.recommended && (
                          <Chip 
                            label="Recommended" 
                            size="small" 
                            color="primary" 
                            sx={{ ml: 1 }}
                          />
                        )}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              {renderUpdateStatus('sigma')}
              <Typography variant="subtitle2" gutterBottom>Sigma Rule Directory</Typography>
              <TextField
                value={ruleDirectories.sigma || ''}
                onChange={(e) => onRuleDirectoryChange('sigma', e.target.value)}
                fullWidth
                variant="outlined"
                sx={{ mb: 2 }}
                helperText="Rule packages are saved and extracted here. Contents are deleted and overwritten upon updating."
              />

              <Typography variant="subtitle2" gutterBottom>Sigma Vector Store Directory</Typography>
              <TextField
                value={vectorStoreDirectories.sigma || ''}
                onChange={(e) => onVectorStoreDirectoryChange('sigma', e.target.value)}
                fullWidth
                variant="outlined"
                helperText="Vector stores will be created here."
              />
              {renderVectorStoreStatus('sigma')}
              {renderActionButtons('sigma', sigmaPackageType)}
            </Box>
          )}

          {/* YARA Settings Tab */}
          {selectedTab === 1 && (
            <Box sx={{ mt: 2 }}>
              <FormControl fullWidth sx={{ mb: 3 }}>
                <InputLabel>YARA Package Type</InputLabel>
                <Select
                  value={yaraPackageType}
                  label="YARA Package Type"
                  onChange={(e) => onYaraPackageTypeChange(e.target.value)}
                >
                  {YARA_PACKAGES.map((pkg) => (
                    <MenuItem key={pkg.value} value={pkg.value}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                        <Box>
                          {pkg.label}
                          <Typography variant="caption" color="textSecondary" display="block">
                            {pkg.description}
                          </Typography>
                        </Box>
                        {pkg.recommended && (
                          <Chip 
                            label="Recommended" 
                            size="small" 
                            color="primary" 
                            sx={{ ml: 1 }}
                          />
                        )}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              {renderUpdateStatus('yara')}
              <Typography variant="subtitle2" gutterBottom>YARA Rule Directory</Typography>
              <TextField
                value={ruleDirectories.yara || ''}
                onChange={(e) => onRuleDirectoryChange('yara', e.target.value)}
                fullWidth
                variant="outlined"
                sx={{ mb: 2 }}
                helperText="Rule packages are saved and extracted here. Contents are deleted and overwritten upon updating."
              />

              <Typography variant="subtitle2" gutterBottom>YARA Vector Store Directory</Typography>
              <TextField
                value={vectorStoreDirectories.yara || ''}
                onChange={(e) => onVectorStoreDirectoryChange('yara', e.target.value)}
                fullWidth
                variant="outlined"
                helperText="Vector stores will be created here."
              />
              {renderVectorStoreStatus('yara')}
              {renderActionButtons('yara', yaraPackageType)}
            </Box>
          )}

          {/* Snort Settings Tab */}
          {selectedTab === 2 && (
            <Box sx={{ mt: 2 }}>
              {renderUpdateStatus('snort')}
              <Typography variant="subtitle2" gutterBottom>Snort Rule Directory</Typography>
              <TextField
                value={ruleDirectories.snort || ''}
                onChange={(e) => onRuleDirectoryChange('snort', e.target.value)}
                fullWidth
                variant="outlined"
                sx={{ mb: 2 }}
                helperText="Rule packages are saved and extracted here. Contents are deleted and overwritten upon updating."
              />

              <Typography variant="subtitle2" gutterBottom>Snort Vector Store Directory</Typography>
              <TextField
                value={vectorStoreDirectories.snort || ''}
                onChange={(e) => onVectorStoreDirectoryChange('snort', e.target.value)}
                fullWidth
                variant="outlined"
                helperText="Vector stores will be created here."
              />
              {renderVectorStoreStatus('snort')}
              {renderActionButtons('snort')}
            </Box>
          )}

          {/* Snort Settings Tab */}
          {selectedTab === 3 && (
            <Box sx={{ mt: 3 }}>
              {renderUpdateStatus('generated')}
              <Typography variant="subtitle2" gutterBottom>Generated Rule Directory</Typography>
              <TextField
                value={ruleDirectories.generated || ''}
                onChange={(e) => onRuleDirectoryChange('generated', e.target.value)}
                fullWidth
                variant="outlined"
                sx={{ mb: 2 }}
                helperText="Rule packages are saved and extracted here. Contents are deleted and overwritten upon updating."
              />
            </Box>
          )}
        </CardContent>
      </Card>
      
      <Notification
        open={notification.open}
        message={notification.message}
        type={notification.type}
        onClose={() => setNotification({ ...notification, open: false })}
      />
    </>
  );
} 