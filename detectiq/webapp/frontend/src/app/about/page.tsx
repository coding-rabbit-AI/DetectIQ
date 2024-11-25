'use client';

import { useEffect, useState } from 'react';
import { 
  Box, 
  Card, 
  CircularProgress, 
  Typography, 
  useTheme,
  Container,
  Paper,
  Tabs,
  Tab,
  Fade,
  Grid,
  Stack,
  Chip,
  alpha,
  Link,
  IconButton,
  Tooltip,
  SvgIcon,
  Divider
} from '@mui/material';
import { 
  Description as DescriptionIcon,
  Security as SecurityIcon,
  Code as CodeIcon,
  AutoAwesome as AutoAwesomeIcon,
  Speed as SpeedIcon,
  Hub as HubIcon,
  Shield as ShieldIcon,
  GitHub as GitHubIcon,
  LinkedIn as LinkedInIcon,
  Storage as StorageIcon,
  Psychology as PsychologyIcon,
} from '@mui/icons-material';
import { getLicenseContent } from '@/api/licenses';

// Custom Discord Icon component
const DiscordIcon = (props: any) => (
  <SvgIcon {...props}>
    <path d="M19.27 5.33C17.94 4.71 16.5 4.26 15 4a.09.09 0 0 0-.07.03c-.18.33-.39.76-.53 1.09a16.09 16.09 0 0 0-4.8 0c-.14-.34-.35-.76-.54-1.09c-.01-.02-.04-.03-.07-.03c-1.5.26-2.93.71-4.27 1.33c-.01 0-.02.01-.03.02c-2.72 4.07-3.47 8.03-3.1 11.95c0 .02.01.04.03.05c1.8 1.32 3.53 2.12 5.24 2.65c.03.01.06 0 .07-.02c.4-.55.76-1.13 1.07-1.74c.02-.04 0-.08-.04-.09c-.57-.22-1.11-.48-1.64-.78c-.04-.02-.04-.08-.01-.11c.11-.08.22-.17.33-.25c.02-.02.05-.02.07-.01c3.44 1.57 7.15 1.57 10.55 0c.02-.01.05-.01.07.01c.11.09.22.17.33.26c.04.03.04.09-.01.11c-.52.31-1.07.56-1.64.78c-.04.01-.05.06-.04.09c.32.61.68 1.19 1.07 1.74c.03.01.06.02.09.01c1.72-.53 3.45-1.33 5.25-2.65c.02-.01.03-.03.03-.05c.44-4.53-.73-8.46-3.1-11.95c-.01-.01-.02-.02-.04-.02zM8.52 14.91c-1.03 0-1.89-.95-1.89-2.12s.84-2.12 1.89-2.12c1.06 0 1.9.96 1.89 2.12c0 1.17-.84 2.12-1.89 2.12zm6.97 0c-1.03 0-1.89-.95-1.89-2.12s.84-2.12 1.89-2.12c1.06 0 1.9.96 1.89 2.12c0 1.17-.83 2.12-1.89 2.12z"/>
  </SvgIcon>
);

export default function AboutPage() {
  const theme = useTheme();
  const [tabValue, setTabValue] = useState(0);
  const [licenses, setLicenses] = useState({
    sigma: '',
    yara: '',
    snort: ''
  });
  const [loading, setLoading] = useState(true);

  const DETECTIQ_PURPLE = '#9C7EF3'; // Exact color from the logo

  const features = [
    {
      icon: <AutoAwesomeIcon fontSize="large" />,
      title: "AI-Powered Detection",
      description: "Leverage advanced AI models to create, analyze, and optimize detection rules across multiple platforms."
    },
    {
      icon: <PsychologyIcon fontSize="large" />,
      title: "Contextual Rule Creation",
      description: "Enhance AI rule generation by incorporating context from community-tested rule repositories like SigmaHQ, YARA-Forge, and Snort3 Community Rulesets."
    },
    {
      icon: <StorageIcon fontSize="large" />,
      title: "Static Analysis Integration",
      description: "Improve rule accuracy through automated static analysis of files, PCAPs, and logs, providing real-world context to the AI engine."
    },
    {
      icon: <HubIcon fontSize="large" />,
      title: "Multi-Platform Integration",
      description: "Seamlessly integrate with Splunk, Elastic, Microsoft Defender XDR, and other leading security platforms."
    },
    {
      icon: <SpeedIcon fontSize="large" />,
      title: "Automated Workflows",
      description: "Create custom workflows to automate rule creation, testing, and deployment processes."
    },
    {
      icon: <ShieldIcon fontSize="large" />,
      title: "Rule Management",
      description: "Centralized management of Sigma, YARA, and Snort rules with version control and deployment tracking."
    }
  ];

  useEffect(() => {
    const fetchLicenses = async () => {
      try {
        const [sigma, yara, snort] = await Promise.all([
          getLicenseContent('sigma'),
          getLicenseContent('yara'),
          getLicenseContent('snort')
        ]);
        setLicenses({ sigma, yara, snort });
      } catch (error) {
        console.error('Error fetching licenses:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchLicenses();
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 6 }}>
      <Stack spacing={6} alignItems="center" sx={{ width: '100%' }}>
        {/* Hero Section - Updated with exact logo color */}
        <Paper 
          elevation={0} 
          sx={{ 
            p: { xs: 3, md: 6 }, 
            width: '100%',
            background: theme.palette.background.paper,
            borderLeft: `6px solid ${DETECTIQ_PURPLE}`, // Updated border color
            borderRadius: 2,
            textAlign: 'center'
          }}
        >
          <Typography 
            variant="h3" 
            gutterBottom 
            fontWeight="bold"
            sx={{ 
              color: DETECTIQ_PURPLE, // Updated to match logo color
              mb: 3
            }}
          >
            DetectIQ
          </Typography>
          <Typography 
            variant="h6" 
            sx={{ mb: 3 }}
            color="text.primary"
          >
            Advanced Detection Engineering with AI
          </Typography>
          <Typography 
            variant="body1" 
            color="text.secondary"
            sx={{ maxWidth: '800px', mx: 'auto' }}
          >
            Empowering detection engineers with AI-driven tools for creating, managing, and deploying detection rules across multiple platforms.
          </Typography>
        </Paper>

        {/* Development Status Banner */}
        <Paper 
          elevation={0}
          sx={{ 
            p: 2,
            width: '100%',
            backgroundColor: alpha(theme.palette.info.main, 0.1),
            borderRadius: 2,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 1
          }}
        >
          <Typography 
            variant="body1" 
            color="info.main"
            sx={{ 
              display: 'flex', 
              alignItems: 'center',
              gap: 1
            }}
          >
            🚧 Features below are currently in active development, use at own risk, bugs are expected!
          </Typography>
        </Paper>

        {/* Features Grid - Updated to 2x3 grid */}
        <Grid container spacing={4} sx={{ width: '100%' }}>
          {features.map((feature, index) => (
            <Grid item xs={12} md={6} lg={4} key={index}>
              <Card sx={{ 
                height: '100%', 
                p: 4, 
                display: 'flex', 
                flexDirection: 'column',
                position: 'relative',
                transition: 'transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: theme.shadows[4],
                }
              }}>
                <Box sx={{ 
                  position: 'absolute',
                  top: 16,
                  right: 16,
                }}>
                  <Chip 
                    label="In Development" 
                    size="small"
                    sx={{ 
                      backgroundColor: alpha(theme.palette.primary.main, 0.1),
                      color: theme.palette.primary.main,
                      fontSize: '0.75rem'
                    }}
                  />
                </Box>
                <Box sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  mb: 3, 
                  color: theme.palette.primary.main 
                }}>
                  {feature.icon}
                  <Typography variant="h6" sx={{ ml: 2 }}>
                    {feature.title}
                  </Typography>
                </Box>
                <Typography 
                  variant="body1" 
                  color="text.secondary"
                  sx={{ 
                    flex: 1,
                    minHeight: '80px' // Ensures consistent card heights
                  }}
                >
                  {feature.description}
                </Typography>
              </Card>
            </Grid>
          ))}
        </Grid>

        {/* Technologies Section */}
        <Card sx={{ p: 4, width: '100%' }}>
          <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
            Technologies & Frameworks
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" gap={1}>
            <Chip label="Python" color="primary" />
            <Chip label="Django" color="primary" />
            <Chip label="Next.js" color="primary" />
            <Chip label="Material-UI" color="primary" />
            <Chip label="Langchain" color="secondary" />
            <Chip label="OpenAI" color="secondary" />
            <Chip label="FAISS" color="secondary" />
            <Chip label="TypeScript" color="primary" />
          </Stack>
        </Card>

        {/* License Section */}
        <Card sx={{ width: '100%' }}>
          <Typography variant="h6" sx={{ p: 3, borderBottom: `1px solid ${theme.palette.divider}` }}>
            Licenses
          </Typography>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs 
              value={tabValue} 
              onChange={(e, newValue) => setTabValue(newValue)}
              variant="fullWidth"
              textColor="primary"
              indicatorColor="primary"
            >
              <Tab 
                icon={<SecurityIcon sx={{ mr: 1 }} />} 
                label="Sigma Rules" 
                iconPosition="start"
              />
              <Tab 
                icon={<CodeIcon sx={{ mr: 1 }} />} 
                label="YARA Rules" 
                iconPosition="start"
              />
              <Tab 
                icon={<DescriptionIcon sx={{ mr: 1 }} />} 
                label="Snort Rules" 
                iconPosition="start"
              />
            </Tabs>
          </Box>

          <TabPanel value={tabValue} index={0}>
            <Box 
              component="pre" 
              sx={{ 
                p: 4,
                m: 0,
                backgroundColor: theme.palette.background.default,
                color: theme.palette.text.primary,
                borderRadius: 1,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontFamily: 'monospace',
                fontSize: '0.875rem',
                maxHeight: '500px',
                overflow: 'auto',
                '&::-webkit-scrollbar': {
                  width: '8px',
                  height: '8px',
                },
                '&::-webkit-scrollbar-thumb': {
                  backgroundColor: theme.palette.primary.main,
                  borderRadius: '4px',
                },
                '&::-webkit-scrollbar-track': {
                  backgroundColor: theme.palette.background.paper,
                },
              }}
            >
              {licenses.sigma}
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box 
              component="pre" 
              sx={{ 
                p: 4,
                m: 0,
                backgroundColor: theme.palette.background.default,
                color: theme.palette.text.primary,
                borderRadius: 1,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontFamily: 'monospace',
                fontSize: '0.875rem',
                maxHeight: '500px',
                overflow: 'auto',
                '&::-webkit-scrollbar': {
                  width: '8px',
                  height: '8px',
                },
                '&::-webkit-scrollbar-thumb': {
                  backgroundColor: theme.palette.primary.main,
                  borderRadius: '4px',
                },
                '&::-webkit-scrollbar-track': {
                  backgroundColor: theme.palette.background.paper,
                },
              }}
            >
              {licenses.yara}
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box 
              component="pre" 
              sx={{ 
                p: 4,
                m: 0,
                backgroundColor: theme.palette.background.default,
                color: theme.palette.text.primary,
                borderRadius: 1,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontFamily: 'monospace',
                fontSize: '0.875rem',
                maxHeight: '500px',
                overflow: 'auto',
                '&::-webkit-scrollbar': {
                  width: '8px',
                  height: '8px',
                },
                '&::-webkit-scrollbar-thumb': {
                  backgroundColor: theme.palette.primary.main,
                  borderRadius: '4px',
                },
                '&::-webkit-scrollbar-track': {
                  backgroundColor: theme.palette.background.paper,
                },
              }}
            >
              {licenses.snort}
            </Box>
          </TabPanel>
        </Card>

        {/* Contact & Links Section */}
        <Card 
          sx={{ 
            p: 4, 
            width: '100%',
            textAlign: 'center',
            background: theme.palette.background.paper,
          }}
        >
          <Stack spacing={3} alignItems="center">
            <Typography variant="h6">
              Developer Contact
            </Typography>
            
            <Typography variant="body1" color="text.primary">
              Developed by Stephen Lincoln
            </Typography>

            <Stack 
              direction="row" 
              spacing={3} 
              justifyContent="center" 
              alignItems="center"
            >
              <Tooltip title="GitHub">
                <IconButton 
                  component="a" 
                  href="https://github.com/slincoln-aiq" 
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{ 
                    color: theme.palette.text.primary,
                    '&:hover': {
                      color: theme.palette.primary.main
                    }
                  }}
                >
                  <GitHubIcon />
                </IconButton>
              </Tooltip>

              <Tooltip title="LinkedIn">
                <IconButton 
                  component="a" 
                  href="https://www.linkedin.com/in/stephen-lincoln-52109065" 
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{ 
                    color: theme.palette.text.primary,
                    '&:hover': {
                      color: theme.palette.primary.main
                    }
                  }}
                >
                  <LinkedInIcon />
                </IconButton>
              </Tooltip>

              <Tooltip title="SigmaHQ Discord">
                <IconButton 
                  component="a" 
                  href="https://discord.gg/27r98bMv6c" 
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{ 
                    color: theme.palette.text.primary,
                    '&:hover': {
                      color: theme.palette.primary.main
                    }
                  }}
                >
                  <DiscordIcon />
                </IconButton>
              </Tooltip>
            </Stack>

            <Typography 
              variant="body2" 
              color="text.secondary"
            >
              Join the{' '}
              <Link 
                href="https://discord.gg/27r98bMv6c"
                target="_blank"
                rel="noopener noreferrer"
                sx={{ 
                  color: theme.palette.primary.main,
                  textDecoration: 'none',
                  '&:hover': {
                    textDecoration: 'underline'
                  }
                }}
              >
                SigmaHQ Discord
              </Link>
              {' '}community for discussions and updates!
            </Typography>
          </Stack>
        </Card>

        {/* Bottom spacing */}
        <Box sx={{ mb: 2 }} />
      </Stack>
    </Container>
  );
}

// TabPanel component
function TabPanel(props: {
  children?: React.ReactNode;
  index: number;
  value: number;
}) {
  const { children, value, index, ...other } = props;

  return (
    <Fade in={value === index}>
      <div
        role="tabpanel"
        hidden={value !== index}
        id={`license-tabpanel-${index}`}
        aria-labelledby={`license-tab-${index}`}
        {...other}
      >
        {value === index && children}
      </div>
    </Fade>
  );
} 