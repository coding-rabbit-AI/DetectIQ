import {
  Box,
  Typography,
  Chip,
  IconButton,
  Tooltip,
} from '@mui/material';
import { Edit as EditIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { Rule } from '@/types/rules';
import { ruleTypeMap, SEVERITY_COLORS } from '@/constants/rules';
import RuleDeployButton from '../../RuleDeployButton';

interface RuleHeaderProps {
  rule: Rule;
  onEdit?: () => void;
  onDelete?: () => void;
  onRuleDeployed?: () => void;
}

const formatSeverity = (severity: any): string => {
  if (!severity || typeof severity !== 'string') return 'Unknown';
  return severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
};

export default function RuleHeader({
  rule,
  onEdit,
  onDelete,
  onRuleDeployed
}: RuleHeaderProps) {
  return (
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
      <Box>
        <Typography variant="h5" component="h2" gutterBottom>
          {rule.title}
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
          <Chip 
            label={ruleTypeMap[rule.type]} 
            color="primary" 
            size="small"
            sx={{
              borderRadius: '8px',
              height: '24px',
              '& .MuiChip-label': {
                px: 1.5,
                fontSize: '0.75rem',
                fontWeight: 500,
              },
              background: 'rgba(97, 84, 163, 0.15)',
              color: '#6154a3',
              border: '1px solid rgba(97, 84, 163, 0.2)',
            }}
          />
          <Chip 
            label={formatSeverity(rule.severity)} 
            color={SEVERITY_COLORS[rule.severity]} 
            size="small" 
          />
          <Chip 
            label={rule.is_enabled ? 'Enabled' : 'Disabled'} 
            color={rule.is_enabled ? 'success' : 'default'} 
            size="small" 
          />
        </Box>
      </Box>
      <Box sx={{ display: 'flex', gap: 1 }}>
        {rule.type === 'sigma' && (
          <RuleDeployButton 
            ruleId={typeof rule.id === 'string' ? parseInt(rule.id, 10) : rule.id} 
            onSuccess={onRuleDeployed}
          />
        )}
        {onEdit && (
          <Tooltip title="Edit Rule">
            <IconButton onClick={onEdit} size="small">
              <EditIcon />
            </IconButton>
          </Tooltip>
        )}
        {onDelete && (
          <Tooltip title="Delete Rule">
            <IconButton onClick={onDelete} size="small" color="error">
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        )}
      </Box>
    </Box>
  );
} 