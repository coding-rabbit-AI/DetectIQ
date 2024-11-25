'use client';

import { useState, useCallback } from 'react';
import { Box, Typography, Button } from '@mui/material';

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

export function ErrorBoundary({ children }: ErrorBoundaryProps) {
  const [error, setError] = useState<Error | null>(null);

  const handleError = useCallback((error: Error) => {
    console.error('Uncaught error:', error);
    setError(error);
  }, []);

  if (error) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh',
          gap: 2,
          p: 3,
          textAlign: 'center',
        }}
      >
        <Typography variant="h4" gutterBottom>
          Something went wrong
        </Typography>
        <Typography color="text.secondary" sx={{ mb: 2 }}>
          {error.message || 'An unexpected error occurred'}
        </Typography>
        <Button
          variant="contained"
          onClick={() => {
            setError(null);
            window.location.reload();
          }}
        >
          Reload Page
        </Button>
      </Box>
    );
  }

  try {
    return <>{children}</>;
  } catch (err) {
    handleError(err as Error);
    return null;
  }
} 