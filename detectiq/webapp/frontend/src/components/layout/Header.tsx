import { Box, Typography } from '@mui/material';
import Image from 'next/image';

export default function Header() {
  return (
    <Box 
      sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        gap: 3,
        width: '100%',
        justifyContent: 'space-between',
        py: 1
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 3 }}>
        <Image
          src="/icons/aiq_stacked_color.svg"
          alt="AttackIQ Logo"
          width={48}
          height={48}
          style={{
            filter: 'drop-shadow(0 0 3px rgba(97, 84, 163, 0.3))'
          }}
        />
        <Typography 
          variant="h5" 
          sx={{
            fontWeight: 600,
            background: 'linear-gradient(45deg, #6154a3, #8075b7)',
            backgroundClip: 'text',
            WebkitBackgroundClip: 'text',
            color: 'transparent',
            textShadow: '0px 2px 4px rgba(0,0,0,0.1)',
            letterSpacing: '-0.5px'
          }}
        >
          Detect<span style={{ color: '#6154a3' }}>IQ</span>
        </Typography>
      </Box>
    </Box>
  );
} 