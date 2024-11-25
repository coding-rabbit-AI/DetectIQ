import {
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
  Box,
  Typography,
  Chip,
  Divider,
  Tab,
  Tabs,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { Rule } from '@/types/rules';
import { useState } from 'react';
import RuleChips from '@/components/rules/common/chips/RuleChips';
import TabPanel from '@/components/common/TabPanel/index';
import MITRETacticChips from '@/components/rules/common/MITRETacticChips';
import MonacoEditorWrapper from '@/components/common/MonacoEditorWrapper';

interface RuleDetailsModalProps {
  rule: Rule;
  open: boolean;
  onClose: () => void;
}

export default function RuleDetailsModal({ rule, open, onClose }: RuleDetailsModalProps) {
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: {
          bgcolor: 'background.paper',
          backgroundImage: 'none',
        }
      }}
    >
      <DialogTitle sx={{ m: 0, p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h6" component="div" sx={{ pr: 4 }}>
          {rule.title}
        </Typography>
        <IconButton
          onClick={onClose}
          sx={{
            position: 'absolute',
            right: 8,
            top: 8,
            color: 'text.secondary',
          }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>

      <Box sx={{ px: 3, py: 1 }}>
        <RuleChips rule={rule} />
        {rule.tags?.map((tag: string) => (
          <Chip
            key={tag}
            label={tag}
            size="small"
            sx={{ bgcolor: 'background.default' }}
          />
        ))}
      </Box>

      <Divider sx={{ my: 1 }} />

      <Box sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}>
        <Tabs 
          value={tabValue} 
          onChange={handleTabChange}
          sx={{
            '& .MuiTab-root': {
              minWidth: 120,
              '&.Mui-selected': {
                color: '#6154a3',
                position: 'relative',
                '&::after': {
                  content: '""',
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  right: 0,
                  height: 2,
                  background: 'linear-gradient(90deg, #6154a3, #8075b7)',
                }
              }
            }
          }}
        >
          <Tab label="Overview" />
          <Tab label="Rule Content" />
          <Tab label="Metadata" />
        </Tabs>
      </Box>

      <DialogContent sx={{ minHeight: '60vh' }}>
        <TabPanel value={tabValue} index={0}>
          <Typography variant="body1" gutterBottom>
            {rule.description}
          </Typography>
          
          {rule.metadata?.mitre_attack?.tactics && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="h6" gutterBottom>MITRE ATT&CK</Typography>
              <MITRETacticChips tactics={rule.metadata.mitre_attack.tactics} />
            </Box>
          )}
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Box sx={{ height: 'calc(100vh - 400px)' }}>
            <MonacoEditorWrapper
              content={rule.content}
              language={rule.type === 'sigma' ? 'yaml' : rule.type === 'yara' ? 'yara' : 'plaintext'}
              height="100%"
              readOnly
            />
          </Box>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <Box
            component="pre"
            sx={{
              p: 2,
              borderRadius: 1,
              bgcolor: 'background.default',
              overflow: 'auto',
              fontSize: '0.875rem',
              fontFamily: 'monospace',
            }}
          >
            {JSON.stringify(rule.metadata, null, 2)}
          </Box>
        </TabPanel>
      </DialogContent>
    </Dialog>
  );
} 