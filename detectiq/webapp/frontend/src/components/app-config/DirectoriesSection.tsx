import { Card, CardContent, Typography, Grid, TextField, Box, Button, Alert, CircularProgress } from '@mui/material';
import { Folder as FolderIcon, Storage as StorageIcon } from '@mui/icons-material';
import { useQuery, useMutation } from '@tanstack/react-query';
import { settingsApi } from '@/api/client';
import { useEffect, useState } from 'react';

interface DirectoriesSectionProps {
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

export default function DirectoriesSection({
  ruleDirectories,
  vectorStoreDirectories,
  onRuleDirectoryChange,
  onVectorStoreDirectoryChange,
}: DirectoriesSectionProps) {
  // Add state to track ongoing operations per rule type
  const [creatingVectorstores, setCreatingVectorstores] = useState<{[key: string]: boolean}>({});
  const [updatingPackages, setUpdatingPackages] = useState<{[key: string]: boolean}>({});

  const { data: vectorstoreStatus, refetch: refetchVectorstores } = useQuery({
    queryKey: ['vectorstoreStatus'],
    queryFn: settingsApi.checkVectorstores,
  });

  // Add query for rule package status
  const { data: rulePackageStatus, refetch: refetchPackages } = useQuery({
    queryKey: ['rulePackageStatus'],
    queryFn: settingsApi.checkRulePackages,
  });

  // Modified mutation with better error handling
  const createVectorstoreMutation = useMutation({
    mutationFn: async (type: string) => {
      try {
        // Set creating state for this specific type
        setCreatingVectorstores(prev => ({ ...prev, [type]: true }));
        
        // Start the creation process
        await settingsApi.createVectorstore(type);
        
        // Poll for completion
        let attempts = 0;
        const maxAttempts = 60; // 5 minutes with 5-second intervals
        
        while (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
          const status = await settingsApi.checkVectorstores();
          
          if (status[type]?.exists) {
            return { success: true };
          }
          attempts++;
        }
        
        throw new Error('Operation timed out');
      } finally {
        // Clear creating state regardless of outcome
        setCreatingVectorstores(prev => ({ ...prev, [type]: false }));
      }
    },
    onSuccess: () => {
      refetchVectorstores();
    },
    onError: (error) => {
      console.error('Error creating vectorstore:', error);
      // The creating state is already cleared in the finally block
    },
  });

  // Add mutation for updating packages
  const updatePackageMutation = useMutation({
    mutationFn: async (type: string) => {
      try {
        setUpdatingPackages(prev => ({ ...prev, [type]: true }));
        await settingsApi.updateRulePackage(type);
        await refetchPackages();
      } finally {
        setUpdatingPackages(prev => ({ ...prev, [type]: false }));
      }
    },
  });

  // Pass the creating state to DirectoryGroup
  return (
    <Card elevation={2}>
      <CardContent>
        <Typography variant="h6" gutterBottom color="primary">
          Directories
        </Typography>
        
        {/* Rule Directories */}
        <DirectoryGroup
          icon={<FolderIcon />}
          title="Rule Directories"
          directories={ruleDirectories}
          onChange={onRuleDirectoryChange}
          labelPrefix="Rules"
          rulePackageStatus={rulePackageStatus}
          onUpdateRulePackage={(type) => updatePackageMutation.mutate(type)}
          isUpdatingPackage={updatingPackages}
        />

        {/* Vector Store Directories */}
        <DirectoryGroup
          icon={<StorageIcon />}
          title="Vector Store Directories"
          directories={vectorStoreDirectories}
          onChange={onVectorStoreDirectoryChange}
          labelPrefix="Vector Store"
          sx={{ mt: 4 }}
          vectorstoreStatus={vectorstoreStatus}
          onCreateVectorstore={(type) => createVectorstoreMutation.mutate(type)}
          isCreatingVectorstore={creatingVectorstores}
        />
      </CardContent>
    </Card>
  );
}

// Update DirectoryGroup props interface
interface DirectoryGroupProps {
  icon: React.ReactNode;
  title: string;
  directories: { [key: string]: string };
  onChange: (type: string, value: string) => void;
  labelPrefix: string;
  sx?: any;
  vectorstoreStatus?: { [key: string]: { exists: boolean } };
  onCreateVectorstore?: (type: string) => void;
  isCreatingVectorstore?: {[key: string]: boolean};
  rulePackageStatus?: { [key: string]: RulePackageStatus };
  onUpdateRulePackage?: (type: string) => void;
  isUpdatingPackage?: {[key: string]: boolean};
}

// Helper component for directory groups
function DirectoryGroup({ 
  icon, 
  title, 
  directories, 
  onChange, 
  labelPrefix, 
  sx = {},
  vectorstoreStatus,
  onCreateVectorstore,
  isCreatingVectorstore = {},
  rulePackageStatus,
  onUpdateRulePackage,
  isUpdatingPackage = {},
}: DirectoryGroupProps) {
  // Add state for client-side rendering
  const [isClient, setIsClient] = useState(false);

  // Use effect to set client-side rendering flag
  useEffect(() => {
    setIsClient(true);
  }, []);

  return (
    <Box sx={sx}>
      <Box sx={{
        display: 'flex',
        alignItems: 'center',
        mb: 2,
        pb: 1,
        borderBottom: '1px solid',
        borderColor: 'divider'
      }}>
        <Box sx={{ mr: 1 }}>{icon}</Box>
        <Typography variant="subtitle1">{title}</Typography>
      </Box>
      <Grid container spacing={2}>
        {Object.entries(directories).map(([type, path]) => (
          <Grid item xs={12} key={type}>
            <Box>
              <TextField
                label={`${type.toUpperCase()} ${labelPrefix} Directory`}
                value={path}
                onChange={(e) => onChange(type, e.target.value)}
                fullWidth
                variant="outlined"
              />
              {rulePackageStatus && rulePackageStatus[type] && (
                <Box sx={{ mt: 1 }}>
                  <Alert 
                    severity={rulePackageStatus[type].needs_update ? "warning" : "success"}
                    action={
                      rulePackageStatus[type].needs_update && onUpdateRulePackage && (
                        <Button
                          color="inherit"
                          size="small"
                          onClick={() => onUpdateRulePackage(type)}
                          disabled={isUpdatingPackage[type]}
                          startIcon={isUpdatingPackage[type] ? <CircularProgress size={20} /> : null}
                        >
                          {isUpdatingPackage[type] ? 'Updating...' : 'Update Package'}
                        </Button>
                      )
                    }
                  >
                    {type.toUpperCase()} rules package: v{rulePackageStatus[type].current_version}
                    {rulePackageStatus[type].needs_update && 
                      ` (v${rulePackageStatus[type].latest_version} available)`
                    }
                  </Alert>
                </Box>
              )}
              {/* Only render Alert on client-side */}
              {isClient && vectorstoreStatus && (
                <Box sx={{ mt: 1 }}>
                  <Alert 
                    severity={vectorstoreStatus[type]?.exists ? "success" : "warning"}
                    action={
                      !vectorstoreStatus[type]?.exists && onCreateVectorstore && (
                        <Button
                          color="inherit"
                          size="small"
                          onClick={() => onCreateVectorstore(type)}
                          disabled={isCreatingVectorstore[type]}
                        >
                          {isCreatingVectorstore[type] ? (
                            <CircularProgress size={20} />
                          ) : (
                            'Create Vectorstore'
                          )}
                        </Button>
                      )
                    }
                  >
                    {type.charAt(0).toUpperCase() + type.slice(1)} vectorstore is 
                    {vectorstoreStatus[type]?.exists ? ' ready' : 
                     isCreatingVectorstore[type] ? ' being created...' : ' not created'}
                  </Alert>
                </Box>
              )}
            </Box>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
} 