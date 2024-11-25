import ReactMarkdown from 'react-markdown';
import { Box, Typography, Paper, Divider } from '@mui/material';

interface AgentAnalysisProps {
  output: string;
}

export default function AgentAnalysisPanel({ output }: AgentAnalysisProps) {
  // Parse different sections from the agent output
  const sections = {
    analysis: output.match(/=== Analysis Summary ===\n([\s\S]*?)(?===|$)/)?.[1]?.trim(),
    detection: output.match(/=== Detection Strategy ===\n([\s\S]*?)(?===|$)/)?.[1]?.trim(),
    validation: output.match(/=== Validation Notes ===\n([\s\S]*?)(?===|$)/)?.[1]?.trim(),
  };

  return (
    <Box>
      {Object.entries(sections).map(([section, content]) => (
        content && (
          <Paper 
            key={section} 
            sx={{ 
              p: 2, 
              mb: 2, 
              bgcolor: 'background.default',
              '&:hover': {
                bgcolor: 'background.paper',
                transition: 'background-color 0.2s',
              }
            }}
          >
            <Typography 
              variant="subtitle1" 
              sx={{ 
                mb: 1,
                color: 'primary.main',
                fontWeight: 600,
                textTransform: 'capitalize'
              }}
            >
              {section.replace(/([A-Z])/g, ' $1').trim()}
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Box 
              sx={{ 
                '& p': { 
                  my: 1,
                  fontSize: '0.875rem',
                  lineHeight: 1.6
                },
                '& ul, & ol': { 
                  pl: 3,
                  my: 1
                },
                '& li': { 
                  fontSize: '0.875rem',
                  lineHeight: 1.6
                },
                '& strong': {
                  fontWeight: 600,
                  color: 'text.primary'
                },
                '& code': {
                  backgroundColor: 'action.hover',
                  padding: '2px 4px',
                  borderRadius: 1,
                  fontSize: '0.8125rem',
                  color: 'primary.main'
                }
              }}
            >
              <ReactMarkdown>{content || ''}</ReactMarkdown>
            </Box>
          </Paper>
        )
      ))}
    </Box>
  );
} 