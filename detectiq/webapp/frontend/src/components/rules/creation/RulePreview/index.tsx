import { Box, Typography, Card, CardContent, Button, useTheme } from '@mui/material';
import { Edit as EditIcon, Save as SaveIcon } from '@mui/icons-material';
import { useState, useEffect } from 'react';
import { useMutation } from '@tanstack/react-query';
import { rulesApi } from '@/api/client';
import MonacoEditorWrapper from '@/components/common/MonacoEditorWrapper';

interface RulePreviewProps {
  content: string | null;
  title: string;
  ruleType?: 'sigma' | 'yara' | 'snort';
  ruleId?: string | number | null;
  onUpdate?: () => void;
}

export default function RulePreview({ 
  content, 
  title, 
  ruleType = 'sigma',
  ruleId,
  onUpdate 
}: RulePreviewProps) {
  const theme = useTheme();
  const [isEditing, setIsEditing] = useState(false);
  const [editedContent, setEditedContent] = useState<string>(content ?? '');

  const languageMap = {
    sigma: 'yaml',
    yara: 'yara',
    snort: 'plaintext',
  };

  useEffect(() => {
    setEditedContent(content ?? '');
  }, [content]);

  const updateRuleMutation = useMutation({
    mutationFn: async (content: string) => {
      if (!ruleId) throw new Error('Rule ID is required for updates');
      const id = typeof ruleId === 'number' ? ruleId.toString() : ruleId;
      await rulesApi.updateRule(id, {
        content,
        type: ruleType,
      });
    },
    onSuccess: () => {
      setIsEditing(false);
      onUpdate?.();
    },
  });

  const handleSave = () => {
    if (editedContent && ruleId) {
      updateRuleMutation.mutate(editedContent);
    }
  };

  const handleEdit = () => {
    setEditedContent(content ?? '');
    setIsEditing(true);
  };

  const handleContentChange = (value: string | undefined) => {
    if (value !== undefined) {
      setEditedContent(value);
    }
  };

  // Add Monaco editor options
  const editorOptions = {
    minimap: { enabled: false },
    lineNumbers: 'on',
    lineDecorationsWidth: 0,
    lineNumbersMinChars: 3,
    glyphMargin: false,
    folding: true,
    scrollBeyondLastLine: false,
    readOnly: !isEditing,
    renderLineHighlight: 'none',
    // Customize line decoration colors
    'editorLineNumber.foreground': theme.palette.text.disabled,
    'editor.lineHighlightBackground': theme.palette.action.hover,
    'editor.lineHighlightBorder': 'transparent',
    'editorGutter.background': theme.palette.background.paper,
  };

  return (
    <Box sx={{ 
      height: '100%', 
      display: 'flex', 
      flexDirection: 'column',
      minHeight: '500px'
    }}>
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'flex-end', 
        gap: 1, 
        mb: 1 
      }}>
        {ruleId && (
          isEditing ? (
            <Button
              startIcon={<SaveIcon />}
              onClick={handleSave}
              disabled={updateRuleMutation.isPending}
              size="small"
            >
              Save
            </Button>
          ) : (
            <Button
              startIcon={<EditIcon />}
              onClick={handleEdit}
              size="small"
            >
              Edit
            </Button>
          )
        )}
      </Box>

      <MonacoEditorWrapper
        content={isEditing ? editedContent : content}
        language={languageMap[ruleType] || 'plaintext'}
        height="100%"
        readOnly={!isEditing}
        onChange={handleContentChange}
        options={editorOptions}
      />
    </Box>
  );
} 