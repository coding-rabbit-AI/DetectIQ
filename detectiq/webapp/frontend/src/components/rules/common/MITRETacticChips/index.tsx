import { Box, Chip } from '@mui/material';

interface MITRETacticChipsProps {
  tactics: string[];
  size?: 'small' | 'medium';
}

export default function MITRETacticChips({ tactics, size = 'small' }: MITRETacticChipsProps) {
  return (
    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
      {tactics.map((tactic) => (
        <Chip
          key={tactic}
          label={tactic}
          size={size}
          sx={{ bgcolor: 'background.default' }}
        />
      ))}
    </Box>
  );
} 