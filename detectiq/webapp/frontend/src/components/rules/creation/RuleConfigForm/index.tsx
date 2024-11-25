import {
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Typography
} from '@mui/material';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import { RuleType } from '@/types/rules';
import { RULE_TYPE_LABELS } from '@/constants/rules';

interface RuleConfigFormProps {
  ruleType: RuleType;
  description: string;
  file: File | null;
  isLoading: boolean;
  error: string | null;
  onRuleTypeChange: (type: RuleType) => void;
  onDescriptionChange: (description: string) => void;
  onFileChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
  onSubmit: (e: React.FormEvent) => Promise<void>;
}

export default function RuleConfigForm({
  ruleType,
  description,
  file,
  isLoading,
  error,
  onRuleTypeChange,
  onDescriptionChange,
  onFileChange,
  onSubmit
}: RuleConfigFormProps) {
  const canUploadFile = ruleType !== 'sigma';
  const acceptedFiles = ruleType === 'snort' ? '.pcap' : '*';

  return (
    <Box>
      <FormControl fullWidth sx={{ mb: 2 }}>
        <InputLabel>Rule Type</InputLabel>
        <Select
          value={ruleType}
          label="Rule Type"
          onChange={(e) => onRuleTypeChange(e.target.value as RuleType)}
        >
          {Object.entries(RULE_TYPE_LABELS).map(([key, value]) => (
            <MenuItem key={key} value={key}>{value}</MenuItem>
          ))}
        </Select>
      </FormControl>

      <TextField
        label="Description"
        multiline
        rows={8}
        value={description}
        onChange={(e) => onDescriptionChange(e.target.value)}
        fullWidth
        sx={{ mb: 2 }}
        placeholder="Describe what you want to detect..."
      />

      <Box sx={{ mb: 2 }}>
        <input
          accept={acceptedFiles}
          style={{ display: 'none' }}
          id="file-upload"
          type="file"
          onChange={onFileChange}
          disabled={!canUploadFile}
        />
        <label htmlFor="file-upload">
          <Button
            variant="outlined"
            component="span"
            fullWidth
            disabled={!canUploadFile || isLoading}
            startIcon={<UploadFileIcon />}
          >
            {canUploadFile 
              ? ruleType === 'snort'
                ? 'Upload PCAP File for Analysis'
                : 'Upload File for Analysis'
              : 'File Analysis Not Yet Available for Sigma Rules'}
          </Button>
        </label>
        {file && (
          <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
            Selected file: {file.name}
          </Typography>
        )}
      </Box>

      <Button
        variant="contained"
        onClick={onSubmit}
        disabled={isLoading || (!description && !file)}
        fullWidth
      >
        {isLoading ? <CircularProgress size={24} /> : 'Create Rule'}
      </Button>

      {error && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {error}
        </Alert>
      )}
    </Box>
  );
} 