import { Box, Typography } from '@mui/material';
import ScrollableBox from '@/components/common/ScrollableBox';
import MonacoEditorWrapper from '@/components/common/MonacoEditorWrapper';

interface CodePreviewProps {
  content: string | null;
  title?: string;
  language?: string;
  readOnly?: boolean;
  height?: string;
  onChange?: (value: string | undefined) => void;
}

export default function CodePreview({ 
  content, 
  title,
  language,
  readOnly = true,
  height = '100%',
  onChange
}: CodePreviewProps) {
  const handleChange = (value: string | undefined) => {
    if (value !== undefined && onChange) {
      onChange(value);
    }
  };

  if (!content) {
    return (
      <Typography color="text.secondary">
        Content will appear here
      </Typography>
    );
  }

  if (language) {
    return (
      <Box sx={{ 
        height: '100%',
        borderRadius: 1,
        overflow: 'hidden',
      }}>
        <MonacoEditorWrapper
          content={content}
          language={language}
          readOnly={readOnly}
          height={height}
          onChange={handleChange}
        />
      </Box>
    );
  }

  return (
    <ScrollableBox>
      <pre style={{ 
        margin: 0,
        whiteSpace: 'pre-wrap',
        wordWrap: 'break-word',
        fontSize: '0.875rem',
        lineHeight: 1.6,
      }}>
        {content}
      </pre>
    </ScrollableBox>
  );
} 