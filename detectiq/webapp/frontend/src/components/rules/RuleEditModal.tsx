'use client';

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Typography,
  Alert,
} from '@mui/material';
import { DetectionRule, RuleSeverity } from '@/types/rules';
import { useRuleStore } from '@/store/ruleStore';
import { rulesApi } from '@/api/client';

interface RuleEditModalProps {
  open: boolean;
  onClose: () => void;
  rule: DetectionRule | null;
}

export default function RuleEditModal({ open, onClose, rule }: RuleEditModalProps) {
  const [editedRule, setEditedRule] = useState<Partial<DetectionRule>>({});
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (rule) {
      setEditedRule(rule);
    }
  }, [rule]);

  const handleChange = (field: keyof DetectionRule, value: any) => {
    setEditedRule(prev => ({ ...prev, [field]: value }));
  };

  const handleSave = async () => {
    if (!rule?.id) return;

    try {
      setIsSaving(true);
      setError(null);
      await rulesApi.updateRule(rule.id, editedRule);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save rule');
    } finally {
      setIsSaving(false);
    }
  };

  if (!rule) return null;

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: {
          bgcolor: 'background.paper',
          backgroundImage: 'none',
        }
      }}
    >
      <DialogTitle>Edit Rule: {rule.title}</DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
          <TextField
            label="Title"
            value={editedRule.title || ''}
            onChange={(e) => handleChange('title', e.target.value)}
            fullWidth
          />

          <TextField
            label="Description"
            value={editedRule.description || ''}
            onChange={(e) => handleChange('description', e.target.value)}
            multiline
            rows={3}
            fullWidth
          />

          <FormControl fullWidth>
            <InputLabel>Severity</InputLabel>
            <Select
              value={editedRule.severity || ''}
              label="Severity"
              onChange={(e) => handleChange('severity', e.target.value)}
            >
              {['low', 'medium', 'high', 'critical'].map((severity) => (
                <MenuItem key={severity} value={severity}>
                  {severity}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <TextField
            label="Rule Content"
            value={editedRule.content || ''}
            onChange={(e) => handleChange('content', e.target.value)}
            multiline
            rows={10}
            fullWidth
            sx={{ fontFamily: 'monospace' }}
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={isSaving}>
          Cancel
        </Button>
        <Button 
          onClick={handleSave} 
          variant="contained" 
          disabled={isSaving}
          sx={{ bgcolor: 'primary.main' }}
        >
          {isSaving ? 'Saving...' : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  );
} 