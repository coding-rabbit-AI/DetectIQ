'use client';

import { createTheme } from '@mui/material';
import type { ThemeOptions } from '@mui/material';

declare module '@mui/material' {
  interface Theme {
    // Add any custom theme properties here if needed
  }
  interface ThemeOptions {
    // Add any custom theme options here if needed
  }
}

export const themeOptions: ThemeOptions = {
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
      light: '#e3f2fd',
      dark: '#42a5f5',
      contrastText: '#000000',
    },
    secondary: {
      main: '#ce93d8',
      light: '#f3e5f5',
      dark: '#ab47bc',
      contrastText: '#000000',
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e',
    },
    text: {
      primary: '#ffffff',
      secondary: 'rgba(255, 255, 255, 0.7)',
    },
    divider: 'rgba(255, 255, 255, 0.12)',
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          scrollbarColor: "#6b6b6b #2b2b2b",
          "&::-webkit-scrollbar, & *::-webkit-scrollbar": {
            backgroundColor: "#2b2b2b",
          },
          "&::-webkit-scrollbar-thumb, & *::-webkit-scrollbar-thumb": {
            borderRadius: 8,
            backgroundColor: "#6b6b6b",
            minHeight: 24,
            border: "3px solid #2b2b2b",
          },
          "&::-webkit-scrollbar-thumb:focus, & *::-webkit-scrollbar-thumb:focus": {
            backgroundColor: "#959595",
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
          textTransform: 'none',
          transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
          '&:hover': {
            transform: 'translateY(-1px)',
            boxShadow: '0 4px 12px rgba(97, 84, 163, 0.2)',
          },
          '&:active': {
            transform: 'translateY(0)',
          },
        },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
          '&:hover': {
            transform: 'scale(1.1)',
            backgroundColor: 'rgba(97, 84, 163, 0.1)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          transition: 'all 0.2s ease-in-out',
          '&:hover': {
            transform: 'translateY(-1px)',
          },
        },
      },
    },
    MuiListItem: {
      styleOverrides: {
        root: {
          '&.Mui-selected': {
            backgroundColor: '#42a5f5',
            '&:hover': {
              backgroundColor: '#90caf9',
            },
          },
        },
      },
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h4: {
      fontWeight: 600,
      letterSpacing: '-0.5px',
    },
    h5: {
      fontWeight: 600,
      letterSpacing: '-0.5px',
    },
    subtitle1: {
      letterSpacing: '0.15px',
    },
    body1: {
      letterSpacing: '0.15px',
      lineHeight: 1.6,
    },
  },
};

export const theme = createTheme(themeOptions); 

const loadingAnimation = {
  '@keyframes shimmer': {
    '0%': {
      backgroundPosition: '-200px 0',
    },
    '100%': {
      backgroundPosition: '200px 0',
    },
  },
  animation: 'shimmer 1.5s infinite linear',
  background: 'linear-gradient(to right, #2d2d2d 4%, #3d3d3d 25%, #2d2d2d 36%)',
  backgroundSize: '400px 100%',
}; 