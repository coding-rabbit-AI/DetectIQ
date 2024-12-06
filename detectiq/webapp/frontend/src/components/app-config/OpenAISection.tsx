import { Card, CardContent, Typography, TextField, Box, FormControl, InputLabel, Select, MenuItem, Chip } from '@mui/material';
import { Key as ApiKeyIcon } from '@mui/icons-material';

interface OpenAISectionProps {
  apiKey: string;
  llmModel: string;
  embeddingsModel: string;
  temperature: number;
  onChange: (field: 'apiKey' | 'llmModel' | 'embeddingsModel' | 'temperature', value: string | number) => void;
}

export const LLM_MODELS = [
  { value: 'gpt-4o', label: 'gpt-4o', recommended: true },
  { value: 'gpt-4o-latest', label: 'gpt-4o-latest' },
  { value: 'gpt-4o-mini', label: 'gpt-4o-mini' },
  { value: 'o1-preview', label: 'o1-preview' },
  { value: 'o1-mini', label: 'o1-mini' },
];

export const embedding_modelS = [
  { value: 'text-embedding-3-small', label: 'text-embedding-3-small', recommended: true },
  { value: 'text-embedding-3-large', label: 'text-embedding-3-large' },
  { value: 'text-embedding-ada-002', label: 'text-embedding-ada-002' },
];

export default function OpenAISection({ 
  apiKey = '', 
  llmModel = LLM_MODELS[0].value, 
  embeddingsModel = embedding_modelS[0].value,
  temperature = 0.1,
  onChange 
}: OpenAISectionProps) {
  const handleTemperatureChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    if (value === '') {
      onChange('temperature', 0);
      return;
    }
    
    const numValue = parseFloat(parseFloat(value).toFixed(2));
    
    if (numValue >= 0 && numValue <= 1) {
      onChange('temperature', numValue);
    }
  };

  return (
    <Card elevation={2}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
          <ApiKeyIcon sx={{ mr: 1 }} color="primary" />
          <Typography variant="h6" color="primary">
            OpenAI Configuration
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <TextField
            label="API Key"
            value={apiKey}
            onChange={(e) => onChange('apiKey', e.target.value)}
            fullWidth
            type="password"
            variant="outlined"
            placeholder="Enter your OpenAI API key"
          />

          <TextField
            label="Temperature"
            value={temperature}
            onChange={handleTemperatureChange}
            type="number"
            inputProps={{
              step: 0.01,
              min: 0,
              max: 1,
            }}
            fullWidth
            variant="outlined"
            placeholder="Enter temperature (0.00-1.00)"
            helperText="Controls randomness in responses. Lower values are more focused, higher values more creative."
          />

          <FormControl fullWidth>
            <InputLabel>LLM Model</InputLabel>
            <Select
              value={llmModel}
              label="LLM Model"
              onChange={(e) => onChange('llmModel', e.target.value)}
            >
              {LLM_MODELS.map((model) => (
                <MenuItem key={model.value} value={model.value}>
                  <Box sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between',
                    width: '100%' 
                  }}>
                    {model.label}
                    {model.recommended && (
                      <Chip 
                        label="Recommended" 
                        size="small" 
                        color="primary" 
                        sx={{ ml: 1 }}
                      />
                    )}
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl fullWidth>
            <InputLabel>Embeddings Model</InputLabel>
            <Select
              value={embeddingsModel}
              label="Embeddings Model"
              onChange={(e) => onChange('embeddingsModel', e.target.value)}
            >
              {embedding_modelS.map((model) => (
                <MenuItem key={model.value} value={model.value}>
                  <Box sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between',
                    width: '100%' 
                  }}>
                    {model.label}
                    {model.recommended && (
                      <Chip 
                        label="Recommended" 
                        size="small" 
                        color="primary" 
                        sx={{ ml: 1 }}
                      />
                    )}
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>
      </CardContent>
    </Card>
  );
} 