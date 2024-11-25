import React from 'react';
import { Grid, Alert } from '@mui/material';
import { Rule } from '@/types/rules';
import RuleCard from './RuleCard';
import RuleListSkeleton from './RuleListSkeleton';

interface RuleListProps {
  rules: Rule[];
  isLoading?: boolean;
  onRuleClick: (rule: Rule) => void;
  onMenuClick: (e: React.MouseEvent<HTMLButtonElement>, rule: Rule) => void;
  onDeploySuccess: (integration: string) => void;
}

export default function RuleList({ 
  rules, 
  isLoading = false,
  onRuleClick, 
  onMenuClick, 
  onDeploySuccess 
}: RuleListProps) {
  if (isLoading) {
    return <RuleListSkeleton />;
  }

  if (!rules.length) {
    return (
      <Grid item xs={12}>
        <Alert severity="info">No rules found</Alert>
      </Grid>
    );
  }

  return (
    <Grid container spacing={3}>
      {rules.map((rule) => (
        <Grid item xs={12} sm={6} lg={4} xl={3} key={rule.id}>
          <RuleCard
            rule={rule}
            onRuleClick={onRuleClick}
            onMenuClick={onMenuClick}
            onDeploySuccess={onDeploySuccess}
          />
        </Grid>
      ))}
    </Grid>
  );
} 