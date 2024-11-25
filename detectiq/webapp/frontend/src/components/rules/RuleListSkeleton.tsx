import { Grid, Box, Card, CardContent } from '@mui/material';

const LoadingSkeleton = () => (
  <Card>
    <CardContent>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <Box sx={{ width: '100%' }}>
          <Box
            sx={{
              background: 'linear-gradient(90deg, #2a2a2a 25%, #3a3a3a 50%, #2a2a2a 75%)',
              backgroundSize: '200% 100%',
              animation: 'shimmer 1.5s infinite linear',
              '@keyframes shimmer': {
                '0%': { backgroundPosition: '200% 0' },
                '100%': { backgroundPosition: '-200% 0' },
              },
              borderRadius: 1,
              height: '24px',
              width: '60%',
              mb: 2
            }}
          />
          <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
            {[1, 2, 3].map((i) => (
              <Box
                key={i}
                sx={{
                  background: 'linear-gradient(90deg, #2a2a2a 25%, #3a3a3a 50%, #2a2a2a 75%)',
                  backgroundSize: '200% 100%',
                  animation: 'shimmer 1.5s infinite linear',
                  borderRadius: '8px',
                  height: '24px',
                  width: '80px'
                }}
              />
            ))}
          </Box>
          <Box
            sx={{
              background: 'linear-gradient(90deg, #2a2a2a 25%, #3a3a3a 50%, #2a2a2a 75%)',
              backgroundSize: '200% 100%',
              animation: 'shimmer 1.5s infinite linear',
              borderRadius: 1,
              height: '16px',
              width: '100%',
              mb: 1
            }}
          />
        </Box>
      </Box>
    </CardContent>
  </Card>
);

export default function RuleListSkeleton() {
  return (
    <Grid container spacing={3}>
      {[1, 2, 3].map((i) => (
        <Grid item xs={12} key={i}>
          <LoadingSkeleton />
        </Grid>
      ))}
    </Grid>
  );
} 