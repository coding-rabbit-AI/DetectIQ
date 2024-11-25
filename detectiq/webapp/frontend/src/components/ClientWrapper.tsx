'use client';

import { ThemeProvider, StyledEngineProvider, CssBaseline } from '@mui/material';
import { theme } from '@/app/theme.config';
import AppLayout from './layout/AppLayout';

export function ClientWrapper({ children }: { children: React.ReactNode }) {
  return (
    <StyledEngineProvider injectFirst>
      <ThemeProvider theme={theme}>
        <CssBaseline enableColorScheme />
        <div id="portal-root" />
        <AppLayout>{children}</AppLayout>
      </ThemeProvider>
    </StyledEngineProvider>
  );
} 