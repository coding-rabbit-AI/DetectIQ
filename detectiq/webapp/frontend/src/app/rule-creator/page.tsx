'use client';

import { useState } from 'react';
import { Box, Typography, Grid, Card, CardContent, CircularProgress, Container } from '@mui/material';
import { useMutation } from '@tanstack/react-query';
import { rulesApi } from '@/api/client';
import { Rule, RuleType } from '@/types/rules';
import AgentAnalysisPanel from '@/components/rules/AgentAnalysisPanel';
import RuleConfigForm from '@/components/rules/creation/RuleConfigForm';
import PageLayout from '@/components/layout/PageLayout';
import RulePreview from '@/components/rules/creation/RulePreview';
import { FileAnalysisResponse, RuleCreationResponse, RuleCreationRequest } from '@/types/api';

export default function RuleCreator() {
  const [ruleType, setRuleType] = useState<RuleType>('sigma');
  const [description, setDescription] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generatedRule, setGeneratedRule] = useState<string | null>(null);
  const [agentOutput, setAgentOutput] = useState<string | null>(null);
  const [ruleId, setRuleId] = useState<string | null>(null);

  const createRuleMutation = useMutation<RuleCreationResponse, Error, FormData>({
    mutationFn: async (formData: FormData) => {
      const response = await rulesApi.createRule(formData);
      return response as RuleCreationResponse;
    },
    onSuccess: (response) => {
      if (response.content) {
        setGeneratedRule(response.content);
      }
      if (response.agent_output) {
        setAgentOutput(response.agent_output);
      }
      if (response.id) {
        setRuleId(response.id);
      }
      setError(null);
    },
    onError: (error: Error) => {
      setError(`Rule creation failed: ${error.message}`);
      setGeneratedRule(null);
      setAgentOutput(null);
      setRuleId(null);
    },
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!description.trim() && !file) return;

    const formData = new FormData();
    formData.append('description', description);
    formData.append('type', ruleType);
    formData.append('source', 'DetectIQ');
    
    if (file instanceof File) {
      formData.append('file', file);
      console.log('Appending file:', file.name, file.type, file.size);
    }

    try {
      await createRuleMutation.mutateAsync(formData);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to create rule');
    }
  };

  const handleRuleUpdate = async () => {
    if (ruleId) {
      try {
        const updatedRule = await rulesApi.getRule(ruleId);
        setGeneratedRule(updatedRule.content);
      } catch (error) {
        console.error('Failed to fetch updated rule:', error);
      }
    }
  };

  const handleRuleTypeChange = (newType: RuleType) => {
    setRuleType(newType);
    if (newType === 'sigma') {
      setFile(null);
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      setFile(files[0]);
    } else {
      setFile(null);
    }
  };

  return (
    <PageLayout 
      title="Rule Creator" 
      subtitle="Create and analyze detection rules using AI assistance"
    >
      <Container maxWidth="xl">
        <Grid container spacing={3}>
          <Grid item xs={12} sx={{ maxWidth: '1200px', mx: 'auto', width: '100%' }}>
            <RuleConfigForm
              ruleType={ruleType}
              description={description}
              file={file}
              isLoading={createRuleMutation.isPending}
              error={error}
              onRuleTypeChange={setRuleType}
              onDescriptionChange={setDescription}
              onFileChange={handleFileChange}
              onSubmit={handleSubmit}
            />
          </Grid>

          {(generatedRule && !createRuleMutation.isPending) && (
            <Grid item xs={12} sx={{ maxWidth: '1600px', mx: 'auto', width: '100%' }}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Card sx={{ 
                    height: '600px',
                    display: 'flex',
                    flexDirection: 'column',
                    backgroundColor: (theme) => theme.palette.background.paper,
                    borderRadius: 2,
                    boxShadow: (theme) => theme.shadows[2],
                    overflow: 'hidden'
                  }}>
                    <CardContent sx={{ 
                      p: 3, 
                      flexGrow: 1, 
                      display: 'flex', 
                      flexDirection: 'column',
                      height: '100%',
                      overflow: 'hidden'
                    }}>
                      <Typography variant="h6" gutterBottom>
                        Generated Rule
                      </Typography>
                      <Box sx={{ flexGrow: 1 }}>
                        <RulePreview
                          content={generatedRule}
                          title="Generated Rule"
                          ruleType={ruleType}
                          ruleId={ruleId}
                          onUpdate={handleRuleUpdate}
                        />
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Card sx={{ 
                    height: '600px',
                    backgroundColor: (theme) => theme.palette.background.paper,
                    borderRadius: 2,
                    boxShadow: (theme) => theme.shadows[2]
                  }}>
                    <CardContent sx={{ 
                      height: '100%', 
                      display: 'flex', 
                      flexDirection: 'column',
                      p: 3
                    }}>
                      <Typography variant="h6" gutterBottom>
                        Analysis
                      </Typography>
                      <Box sx={{
                        flexGrow: 1,
                        overflow: 'auto'
                      }}>
                        {agentOutput && <AgentAnalysisPanel output={agentOutput} />}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Grid>
          )}

          {createRuleMutation.isPending && (
            <Grid item xs={12} sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
              <CircularProgress size={40} />
            </Grid>
          )}
        </Grid>
      </Container>
    </PageLayout>
  );
} 