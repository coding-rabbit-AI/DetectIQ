import { Card, CardContent, Typography, Grid, TextField, Box } from '@mui/material';
import { Folder as FolderIcon, Storage as StorageIcon } from '@mui/icons-material';

interface DirectoriesSectionProps {
  ruleDirectories: { [key: string]: string };
  vectorStoreDirectories: { [key: string]: string };
  onRuleDirectoryChange: (type: string, value: string) => void;
  onVectorStoreDirectoryChange: (type: string, value: string) => void;
}

export default function DirectoriesSection({
  ruleDirectories,
  vectorStoreDirectories,
  onRuleDirectoryChange,
  onVectorStoreDirectoryChange,
}: DirectoriesSectionProps) {
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
        />

        {/* Vector Store Directories */}
        <DirectoryGroup
          icon={<StorageIcon />}
          title="Vector Store Directories"
          directories={vectorStoreDirectories}
          onChange={onVectorStoreDirectoryChange}
          labelPrefix="Vector Store"
          sx={{ mt: 4 }}
        />
      </CardContent>
    </Card>
  );
}

// Helper component for directory groups
function DirectoryGroup({ icon, title, directories, onChange, labelPrefix, sx = {} }) {
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
            <TextField
              label={`${type.toUpperCase()} ${labelPrefix} Directory`}
              value={path}
              onChange={(e) => onChange(type, e.target.value)}
              fullWidth
              variant="outlined"
            />
          </Grid>
        ))}
      </Grid>
    </Box>
  );
} 