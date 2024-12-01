import { Box, Typography, useTheme } from '@mui/material';

interface PageLayoutProps {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}

export default function PageLayout({ title, subtitle, children }: PageLayoutProps) {
  const theme = useTheme();
  
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
      <Box 
        sx={{ 
          mb: 4,
          position: 'relative',
          '&::after': {
            content: '""',
            position: 'absolute',
            bottom: -8,
            left: 0,
            width: '60px',
            height: '2px',
            background: 'linear-gradient(90deg, #90caf9, #6154a3)',
            borderRadius: '2px',
          }
        }}
      >
        <Typography 
          variant="h4" 
          sx={{
            fontWeight: 500,
            background: 'linear-gradient(45deg, #90caf9, #6154a3)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            letterSpacing: '0.5px',
            mb: subtitle ? 1 : 0,
          }}
        >
          {title}
        </Typography>
        {subtitle && (
          <Typography
            variant="subtitle1"
            sx={{
              color: 'text.secondary',
              opacity: 0.8,
            }}
          >
            {subtitle}
          </Typography>
        )}
      </Box>
      {children}
    </Box>
  );
} 