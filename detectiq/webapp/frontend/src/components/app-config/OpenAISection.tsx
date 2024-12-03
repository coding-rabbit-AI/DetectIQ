import { Card, CardContent, Typography, TextField, Box } from '@mui/material';
import { Key as ApiKeyIcon } from '@mui/icons-material';

interface OpenAISectionProps {
  apiKey: string;
  onChange: (value: string) => void;
}

export default function OpenAISection({ apiKey, onChange }: OpenAISectionProps) {
  return (
    <Card elevation={2}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
          <ApiKeyIcon sx={{ mr: 1 }} color="primary" />
          <Typography variant="h6" color="primary">
            OpenAI Configuration
          </Typography>
        </Box>
        <TextField
          label="API Key"
          value={apiKey}
          onChange={(e) => onChange(e.target.value)}
          fullWidth
          type="password"
          variant="outlined"
          placeholder="Enter your OpenAI API key"
        />
      </CardContent>
    </Card>
  );
} 