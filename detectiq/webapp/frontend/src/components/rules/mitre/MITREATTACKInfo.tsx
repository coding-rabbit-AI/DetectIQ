import React from 'react';
import {
  Box,
  Chip,
  Link,
  Typography,
} from '@mui/material';

interface MITREATTACKInfoProps {
  data: {
    tactics?: string[];
    techniques?: string[];
    subtechniques?: string[];
  };
}

export default function MITREATTACKInfo({ data }: MITREATTACKInfoProps) {
  const renderSection = (title: string, items?: string[]) => {
    if (!items?.length) return null;

    return (
      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
          {title}
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {items.map((item) => {
            const id = item.match(/T\d+(\.\d+)?/)?.[0];
            const url = id 
              ? `https://attack.mitre.org/techniques/${id}/`
              : undefined;

            return (
              <Chip
                key={item}
                label={item}
                size="small"
                component={url ? 'a' : 'div'}
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                clickable={!!url}
                sx={{
                  '&:hover': {
                    backgroundColor: 'primary.light',
                  },
                }}
              />
            );
          })}
        </Box>
      </Box>
    );
  };

  return (
    <Box>
      {renderSection('Tactics', data.tactics)}
      {renderSection('Techniques', data.techniques)}
      {renderSection('Sub-techniques', data.subtechniques)}
    </Box>
  );
} 