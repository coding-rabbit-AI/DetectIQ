import { Box, useTheme } from '@mui/material';
import MonacoEditor from '@monaco-editor/react';
import type * as Monaco from 'monaco-editor/esm/vs/editor/editor.api';

interface MonacoEditorWrapperProps {
  content: string | null;
  language?: string;
  readOnly?: boolean;
  height?: string;
  onChange?: (value: string | undefined) => void;
  options?: Monaco.editor.IStandaloneEditorConstructionOptions;
}

export default function MonacoEditorWrapper({
  content,
  language = 'yaml',
  readOnly = true,
  height = '100%',
  onChange,
  options: customOptions
}: MonacoEditorWrapperProps) {
  const theme = useTheme();

  const editorOptions: Monaco.editor.IStandaloneEditorConstructionOptions = {
    readOnly,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    fontSize: 14, // Slightly increased for better readability
    fontFamily: "'JetBrains Mono', monospace",
    lineNumbers: 'on',
    roundedSelection: true,
    scrollbar: {
      vertical: 'visible',
      horizontal: 'visible',
      useShadows: false,
      verticalScrollbarSize: 8, // Increased for better usability
      horizontalScrollbarSize: 8,
    },
    overviewRulerLanes: 0,
    hideCursorInOverviewRuler: true,
    automaticLayout: true,
    wordWrap: 'on',
    renderLineHighlight: 'none',
    occurrencesHighlight: 'off',
    selectionHighlight: false,
    padding: { top: 12, bottom: 12 },
    cursorStyle: 'line',
    cursorBlinking: 'smooth',
    ...customOptions
  };

  return (
    <Box sx={{ 
      height: '100%',
      borderRadius: 1,
      overflow: 'hidden',
      bgcolor: theme.palette.background.paper,
      boxShadow: theme.shadows[1], // Adding subtle shadow for depth
      '& .monaco-editor': {
        paddingLeft: 1,
        '& .margin-view-overlays .line-numbers': {
          color: theme.palette.text.disabled,
          '&.active-line-number': {
            color: theme.palette.primary.main
          }
        },
        // Remove default border and add custom border-radius if needed
        borderRadius: '4px',
      }
    }}>
      <MonacoEditor
        height={height}
        language={language}
        value={content || ''}
        onChange={onChange}
        options={editorOptions}
        theme="custom-dark"
        beforeMount={(monaco) => {
          monaco.editor.defineTheme('custom-dark', {
            base: theme.palette.mode === 'dark' ? 'vs-dark' : 'vs',
            inherit: true,
            rules: [
              { token: 'comment', foreground: '6A9955', fontStyle: 'italic' },
              { token: 'keyword', foreground: theme.palette.primary.main.replace('#', '') },
              { token: 'string', foreground: theme.palette.secondary.main.replace('#', '') },
              { token: 'number', foreground: theme.palette.primary.light.replace('#', '') },
              { token: 'type', foreground: theme.palette.secondary.light.replace('#', '') },
              { token: 'function', foreground: theme.palette.primary.dark.replace('#', '') },
              { token: 'variable', foreground: theme.palette.text.primary.replace('#', '') },
              // Add more token rules as needed
            ],
            colors: {
              'editor.background': theme.palette.background.default,
              'editor.foreground': theme.palette.text.primary,
              'editor.lineHighlightBackground': theme.palette.action.hover, // Light highlight on hover
              'editor.selectionBackground': theme.palette.primary.light + '40', // 25% opacity
              'editor.inactiveSelectionBackground': theme.palette.primary.light + '20', // 12.5% opacity
              'editor.selectionHighlightBackground': theme.palette.primary.light + '20',
              'editorCursor.foreground': theme.palette.primary.main,
              'editorWhitespace.foreground': theme.palette.text.disabled,
              'editor.lineNumber.foreground': theme.palette.text.disabled,
              'editor.lineNumber.activeForeground': theme.palette.primary.main,
              'scrollbarSlider.background': theme.palette.action.hover + '80', // 50% opacity
              'scrollbarSlider.hoverBackground': theme.palette.primary.light + '80',
              'scrollbarSlider.activeBackground': theme.palette.primary.dark + '80',
              'editor.findMatchBackground': theme.palette.secondary.light + '80',
              'editor.findMatchHighlightBackground': theme.palette.secondary.light + '60',
              'editor.findRangeHighlightBackground': theme.palette.action.hover + '40',
              // Add more color customizations as needed
            }
          });
          monaco.editor.setTheme('custom-dark');
        }}
      />
    </Box>
  );
}
