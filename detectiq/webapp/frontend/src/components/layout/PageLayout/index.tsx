import { Box, Typography } from '@mui/material';

interface PageLayoutProps {
  title: string;
  children: React.ReactNode;
}

export default function PageLayout({ title, children }: PageLayoutProps) {
  return (
    <Box
      sx={{
        animation: 'fadeIn 0.3s ease-in-out',
        '@keyframes fadeIn': {
          from: { opacity: 0, transform: 'translateY(10px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
      }}
    >
      <Typography 
        variant="h4" 
        gutterBottom
        sx={{
          fontWeight: 600,
          background: 'linear-gradient(45deg, #6154a3, #8075b7)',
          backgroundClip: 'text',
          WebkitBackgroundClip: 'text',
          color: 'transparent',
          mb: 4
        }}
      >
        {title}
      </Typography>
      {children}
    </Box>
  );
} 