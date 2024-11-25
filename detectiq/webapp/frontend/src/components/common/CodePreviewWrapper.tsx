import { Box } from '@mui/material';
import CodePreview from './CodePreview';

interface CodePreviewWrapperProps {
  content: string;
  language?: string;
  title?: string;
  height?: string;
}

export default function CodePreviewWrapper({ content, language, title, height }: CodePreviewWrapperProps) {
  return (
    <Box
      sx={{
        height: height || '100%',
        //bgcolor: '#1e1e1e',
        borderRadius: 1,
        overflow: 'hidden',
      }}
    >
      <CodePreview
        content={content}
        language={language}
        title={title}
        height={height}
      />
    </Box>
  );
} 