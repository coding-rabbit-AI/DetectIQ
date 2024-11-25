'use client';

import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  Box,
  CircularProgress,
  Alert,
  Pagination,
} from '@mui/material';
import { useRuleStore } from '@/store/ruleStore';
import RuleFilters from '@/components/rules/RuleFilters';
import { INTEGRATION_LABELS, INTEGRATIONS } from '@/constants/rules';
import RuleDetailsModal from '@/components/rules/RuleDetailsModal';
import { Rule } from '@/types/rules';
import RuleList from '@/components/rules/RuleList';
import Notification from '@/components/common/Notification';
import PageLayout from '@/components/layout/PageLayout';
import { useRules } from '@/hooks/useRules';

export default function Rules() {
  const { filters, setRules } = useRuleStore();
  const [page, setPage] = useState(1);
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
  const [notification, setNotification] = useState<{
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  } | null>(null);
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useRules(filters, page);

  useEffect(() => {
    if (data?.results) {
      setRules(data.results);
    }
  }, [data, setRules]);

  useEffect(() => {
    if (error) {
      setNotification({
        message: error instanceof Error ? error.message : 'Failed to load rules',
        severity: 'error'
      });
    }
  }, [error]);

  useEffect(() => {
    setPage(1);
  }, [filters]);

  const handlePageChange = (_: React.ChangeEvent<unknown>, value: number) => {
    setPage(value);
  };

  const handleRuleClick = (rule: Rule) => {
    setSelectedRule(rule);
  };

  const handleCloseModal = () => {
    setSelectedRule(null);
  };

  const handleMenuClick = (e: React.MouseEvent<HTMLButtonElement>, rule: Rule) => {
    e.stopPropagation();
    // Add your menu handling logic here
  };

  const getIntegrationLabel = (integration: string) => {
    const key = Object.keys(INTEGRATIONS).find(
      k => INTEGRATIONS[k as keyof typeof INTEGRATIONS] === integration
    );
    return key ? INTEGRATION_LABELS[INTEGRATIONS[key as keyof typeof INTEGRATIONS]] : integration;
  };

  const handleRuleDeploySuccess = (integration: string) => {
    setNotification({
      message: `Rule successfully deployed to ${getIntegrationLabel(integration)}`,
      severity: 'success'
    });
    queryClient.invalidateQueries({ queryKey: ['rules'] });
  };

  const handleNotificationClose = () => {
    setNotification(null);
  };

  if (!data && !isLoading && !error) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <Alert severity="error">
          Error: Failed to load rules data
        </Alert>
      </Box>
    );
  }

  if (error instanceof Error) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <Alert severity="error">
          {error.message || 'An error occurred while loading rules'}
        </Alert>
      </Box>
    );
  }

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  const totalPages = data ? Math.ceil(data.count / 10) : 0;

  return (
    <PageLayout title="Rules">
      <RuleFilters />
      
      <RuleList
        rules={data?.results || []}
        onRuleClick={handleRuleClick}
        onMenuClick={handleMenuClick}
        onDeploySuccess={handleRuleDeploySuccess}
      />

      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
        <Pagination
          count={totalPages}
          page={page}
          onChange={handlePageChange}
          color="primary"
        />
      </Box>

      {selectedRule && (
        <RuleDetailsModal
          rule={selectedRule}
          open={!!selectedRule}
          onClose={handleCloseModal}
        />
      )}

      <Notification
        open={Boolean(notification)}
        message={notification?.message || ''}
        severity={notification?.severity || 'success'}
        onClose={handleNotificationClose}
      />
    </PageLayout>
  );
} 