'use client';

import { useState, useCallback } from 'react';
import {
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Chip,
  SelectChangeEvent,
  InputAdornment,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import debounce from 'lodash/debounce';
import { useRuleStore } from '@/store/ruleStore';
import { RuleFilters as RuleFiltersType, RuleType, IntegrationType } from '@/types/rules';
import { ruleTypeMap } from '@/constants/rules';
import { severityOptions } from '@/constants/rules';
import { MITRE_TACTICS, MITRETactic } from '@/constants/mitre';
import { RULE_SOURCES, RULE_TYPES } from '@/constants/rules';
import { AVAILABLE_SOURCES } from '@/constants/rules';

const ruleTypes: RuleType[] = ['sigma', 'yara', 'snort'];
const integrationTypes: IntegrationType[] = ['splunk', 'elastic', 'microsoft_xdr'];

// Add this helper function at the top level
const formatSeverity = (severity: string): string => {
  if (!severity || typeof severity !== 'string') return 'Unknown';
  return severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
};

export default function RuleFilters() {
  const { filters, setFilters } = useRuleStore();
  const [selectedTactics, setSelectedTactics] = useState<string[]>([]);
  const [searchValue, setSearchValue] = useState(filters.search || '');

  // Debounce the search to avoid too many API calls
  const debouncedSearch = useCallback(
    debounce((value: string) => {
      setFilters({ ...filters, search: value });
    }, 500),
    [filters, setFilters]
  );

  const handleFilterChange = (field: keyof RuleFiltersType, value: any) => {
    if (field === 'enabled' && value !== '') {
      setFilters({ ...filters, [field]: value === 'true' });
    } else {
      setFilters({ ...filters, [field]: value });
    }
  };

  const handleTacticChange = (event: SelectChangeEvent<string[]>) => {
    const value = event.target.value as string[];
    setSelectedTactics(value);
    handleFilterChange('mitreTactic', value.length ? value : undefined);
  };

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    setSearchValue(value);
    debouncedSearch(value);
  };

  return (
    <Box sx={{ mb: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
      <TextField
        fullWidth
        variant="outlined"
        placeholder="Search rules..."
        value={searchValue}
        onChange={handleSearchChange}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <SearchIcon />
            </InputAdornment>
          ),
        }}
      />
      
      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <FormControl sx={{ minWidth: 120 }}>
          <InputLabel>Integration</InputLabel>
          <Select
            value={filters.integration || ''}
            label="Integration"
            onChange={(e) => handleFilterChange('integration', e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            {integrationTypes.map((type) => (
              <MenuItem key={type} value={type}>
                {type}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl sx={{ minWidth: 120 }}>
          <InputLabel>Rule Type</InputLabel>
          <Select
            value={filters.type || ''}
            label="Rule Type"
            onChange={(e) => handleFilterChange('type', e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            {ruleTypes.map((type) => (
              <MenuItem key={type} value={type}>
                {ruleTypeMap[type] || type}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl sx={{ minWidth: 120 }}>
          <InputLabel>Severity</InputLabel>
          <Select
            value={filters.severity || ''}
            label="Severity"
            onChange={(e) => handleFilterChange('severity', e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            {severityOptions.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {formatSeverity(option.value)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl sx={{ minWidth: 200 }}>
          <InputLabel>MITRE Tactics</InputLabel>
          <Select
            multiple
            value={selectedTactics}
            label="MITRE Tactics"
            onChange={handleTacticChange}
            renderValue={(selected) => (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {(selected as string[]).map((value) => (
                  <Chip 
                    key={value} 
                    label={MITRE_TACTICS.find(t => t.id === value)?.name || value} 
                    size="small" 
                  />
                ))}
              </Box>
            )}
          >
            {MITRE_TACTICS.map((tactic) => (
              <MenuItem key={tactic.id} value={tactic.id}>
                {tactic.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl sx={{ minWidth: 120 }}>
          <InputLabel>Status</InputLabel>
          <Select
            value={filters.enabled === undefined ? '' : filters.enabled.toString()}
            label="Status"
            onChange={(e) => handleFilterChange('enabled', e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            <MenuItem value="true">Enabled</MenuItem>
            <MenuItem value="false">Disabled</MenuItem>
          </Select>
        </FormControl>

        <FormControl sx={{ minWidth: 120 }}>
          <InputLabel>Source</InputLabel>
          <Select
            value={filters.source || ''}
            label="Source"
            onChange={(e) => handleFilterChange('source', e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            {AVAILABLE_SOURCES.map((source) => (
              <MenuItem key={source} value={source}>
                {source}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>
    </Box>
  );
} 