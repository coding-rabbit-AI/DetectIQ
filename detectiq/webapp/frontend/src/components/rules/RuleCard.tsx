import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  IconButton,
} from '@mui/material';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import { Rule } from '@/types/rules';
import { RULE_TYPES, RULE_SOURCES, INTEGRATIONS, SEVERITY_COLORS, SEVERITY_STYLES } from '@/constants/rules';
import RuleDeployButton from './RuleDeployButton';
import RuleChips from './common/chips/RuleChips';

interface RuleCardProps {
  rule: Rule;
  onRuleClick: (rule: Rule) => void;
  onMenuClick: (e: React.MouseEvent<HTMLButtonElement>, rule: Rule) => void;
  onDeploySuccess: (integration: string) => void;
}

export default function RuleCard({ rule, onRuleClick, onMenuClick, onDeploySuccess }: RuleCardProps) {
  return (
    <Card 
      onClick={() => onRuleClick(rule)} 
      sx={{ 
        cursor: 'pointer',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        transition: 'all 0.2s ease-in-out',
        position: 'relative',
        '&:hover': {
          transform: 'translateY(-4px)',
          boxShadow: '0 4px 20px rgba(97, 84, 163, 0.15)',
        },
        '&::before': {
          content: '""',
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          opacity: 0.03,
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='20' height='20' viewBox='0 0 20 20' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%236154a3' fill-opacity='0.2' fill-rule='evenodd'%3E%3Ccircle cx='3' cy='3' r='3'/%3E%3C/g%3E%3C/svg%3E")`,
        }
      }}
    >
      <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', height: '100%' }}>
          <Box sx={{ 
            flex: 1,
            minWidth: 0,
            display: 'flex',
            flexDirection: 'column'
          }}>
            <Typography variant="h6" noWrap sx={{ mb: 1 }}>
              {rule.title}
            </Typography>
            <Box sx={{ 
              display: 'flex', 
              flexWrap: 'wrap',
              gap: 1,
              mt: 2,
              mb: 2
            }}>
              <RuleChips rule={rule} size="small" />
            </Box>
            <Typography 
              variant="body2" 
              color="textSecondary"
              sx={{
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                display: '-webkit-box',
                WebkitLineClamp: 2,
                WebkitBoxOrient: 'vertical',
                wordBreak: 'break-word'
              }}
            >
              {rule.description}
            </Typography>
          </Box>
          <Box sx={{ ml: 2, flexShrink: 0 }}>
            {rule.type === 'sigma' && (
              <RuleDeployButton 
                ruleId={typeof rule.id === 'string' ? parseInt(rule.id, 10) : rule.id} 
                onSuccess={onDeploySuccess}
              />
            )}
            <IconButton onClick={(e) => onMenuClick(e, rule)} size="small">
              <MoreVertIcon />
            </IconButton>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
} 