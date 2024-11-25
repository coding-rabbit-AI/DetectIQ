import React from 'react';
import { Box, Card, CardContent, Typography, Grid } from '@mui/material';
import { Rule } from '@/types/rules';
import CodePreviewWrapper from '@/components/common/CodePreviewWrapper';
import RuleHeader from './details/RuleHeader';
import RuleMetadata from './details/RuleMetadata';
import MonacoEditorWrapper from '@/components/common/MonacoEditorWrapper';

interface RuleDetailsProps {
  rule: Rule;
  onEdit?: () => void;
  onDelete?: () => void;
  onRuleDeployed?: () => void;
}

export default function RuleDetails({ rule, onEdit, onDelete, onRuleDeployed }: RuleDetailsProps) {
  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <RuleHeader 
            rule={rule}
            onEdit={onEdit}
            onDelete={onDelete}
            onRuleDeployed={onRuleDeployed}
          />
          {rule.description && (
            <Typography variant="body2" color="text.secondary" paragraph>
              {rule.description}
            </Typography>
          )}
        </CardContent>
      </Card>

      <Grid container spacing={2} sx={{ flexGrow: 1 }}>
        <Grid item xs={12} md={8}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Rule Content
              </Typography>
              <MonacoEditorWrapper
                content={rule.content}
                language={rule.type}
                height="100%"
                readOnly
              />
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <RuleMetadata rule={rule} />
        </Grid>
      </Grid>
    </Box>
  );
} 