import { Box, BoxProps } from '@mui/material';

interface ScrollableBoxProps extends BoxProps {
  height?: string | number;
}

export default function ScrollableBox({ height = '100%', children, ...props }: ScrollableBoxProps) {
  return (
    <Box
      sx={{
        height,
        overflowY: 'auto',
        '&::-webkit-scrollbar': {
          width: '8px',
        },
        '&::-webkit-scrollbar-track': {
          background: 'transparent',
        },
        '&::-webkit-scrollbar-thumb': {
          background: '#888',
          borderRadius: '4px',
        },
        '&::-webkit-scrollbar-thumb:hover': {
          background: '#666',
        },
        ...props.sx
      }}
      {...props}
    >
      {children}
    </Box>
  );
} 