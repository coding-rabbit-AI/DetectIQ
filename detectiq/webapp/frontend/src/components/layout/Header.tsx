import { Box, Typography, useTheme } from '@mui/material';
import Image from 'next/image';

export default function Header() {
  const theme = useTheme();
  
  return (
    <Box 
      sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        p: 1.5,
        borderBottom: `1px solid ${theme.palette.divider}`,
        background: 'transparent',
        backdropFilter: 'blur(8px)',
        position: 'sticky',
        top: 0,
        zIndex: theme.zIndex.appBar,
        transition: 'all 0.2s ease-in-out',
        '&::after': {
          content: '""',
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          height: '1px',
          background: 'linear-gradient(90deg, transparent, rgba(144, 202, 249, 0.1), transparent)',
        }
      }}
    >
      <Box 
        sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 1.5,
          '&:hover': {
            '& .logo': {
              transform: 'scale(1.05)',
            },
            '& .text': {
              letterSpacing: '0.8px',
            }
          }
        }}
      >
        <Box 
          className="logo"
          sx={{ 
            transition: 'transform 0.2s ease-in-out',
            display: 'flex',
          }}
        >
          <Image 
            src="/icons/aiq_stacked_color.svg" 
            alt="DetectIQ Logo" 
            width={24} 
            height={24} 
            priority 
          />
        </Box>
        <Typography 
          variant="subtitle1"
          className="text"
          sx={{ 
            fontWeight: 400,
            letterSpacing: '0.5px',
            transition: 'all 0.2s ease-in-out',
            background: 'linear-gradient(45deg, #90caf9, #6154a3)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            opacity: 0.9,
          }}
        >
          DetectIQ
        </Typography>
      </Box>
    </Box>
  );
} 