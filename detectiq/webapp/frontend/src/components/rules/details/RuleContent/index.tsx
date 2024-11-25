import { Box } from '@mui/material';
import CodePreviewWrapper from '@/components/common/CodePreviewWrapper';

interface RuleContentProps {
  content: string;
  language?: string;
}

export default function RuleContent({ content, language }: RuleContentProps) {
  return (
    <Box
      sx={{
        height: 'calc(100vh - 300px)',
        p: 2,
        borderRadius: 1,
        //bgcolor: '#1e1e1e',
        overflow: 'auto',
      }}
    >
      <CodePreviewWrapper
        content={content}
        language={language}
        height="100%"
      />
    </Box>
  );
} 