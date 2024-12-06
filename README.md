# DetectIQ

> ⚠️ **IMPORTANT DISCLAIMER**
> 
> This project is currently a **Proof of Concept** and is under active development:
> - Features are incomplete and actively being developed
> - Bugs and breaking changes are expected
> - Project structure and APIs may change significantly
> - Documentation may be outdated or incomplete
> - Not recommended for production use at this time
> - Security features are still being implemented
> 
> We welcome feedback and contributions, but please use at your own risk!

DetectIQ is an AI-powered security rule management platform that helps create, analyze, and optimize detection rules across multiple security platforms.  It can be used with the provided UI, or just with Python scripts using the self contained `detectiq/core` module.  See examples in the `detectiq/examples` directory for more information.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL_v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-red.svg)]()

- [DetectIQ](#detectiq)
  - [Current Features](#current-features)
    - [AI-Powered Detection 🤖](#ai-powered-detection-)
    - [Rule Repository Integration 📚](#rule-repository-integration-)
    - [Static Analysis Integration 📊](#static-analysis-integration-)
    - [Multi-Platform Integration 🔄](#multi-platform-integration-)
    - [Planned Features](#planned-features)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Configuration](#configuration)
    - [Development](#development)
  - [Project Structure](#project-structure)
  - [Contributing](#contributing)
  - [License](#license)
  - [Support \& Community](#support--community)
  - [Acknowledgments](#acknowledgments)


## Current Features

### AI-Powered Detection 🤖
- Create and optimize detection rules using OpenAI's LLM models
- Intelligent rule suggestions based on context and best practices
- Automated rule validation and testing 
- Provide context for rule creation from static file analysis for YARA rules
- Provide context for rule creation from PCAP analysis for Snort rules

### Rule Repository Integration 📚
- Enhanced by community-tested repositories:
  - SigmaHQ Core Ruleset
  - YARA-Forge Rules
  - Snort3 Community Ruleset
- Automatically keep repositories up-to-date with rule changes
- Vectorize rules for efficient similarity comparison for more context-aware rule creation engine

### Static Analysis Integration 📊
- Automated file analysis for YARA rules
- PCAP analysis for Snort rule creation
- Implicit log analysis for Sigma rule optimization (Explicit Analysis Coming Soon)

### Multi-Platform Integration 🔄
- Automatic Sigma rule translation to various SIEM queries using `pySigma` and `SigmAIQ` wrapper
- Seamlessly create Splunk Enterprise Security correlation rules from Sigma rules

### Planned Features
- Custom/local LLM models, embeddings, and vector stores
- More integrations with SIEMs such as Elastic and Microsoft XDR
- Explicit log analysis for Sigma rule optimization
- Rule testing and validation
- Deployment tracking and workflow automation
- Rule management UI Enhancements

## Getting Started

### Prerequisites
- Python 3.9 or higher
- Node.js 16+
- Poetry for dependency management (optional, but recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/slincoln-aiq/DetectIQ.git

# Install Python dependencies
poetry install --all-extras

# Install frontend dependencies
cd detectiq/webapp/frontend
npm install

# Set up environment
cp .env.example .env
# Edit .env with your settings
```

### Configuration

Required environment variables:
```bash
OPENAI_API_KEY="your-api-key"
DETECTIQ_RULE_DIR="path/to/rules"
DETECTIQ_VECTOR_STORE_DIR="path/to/vectorstore"
DETECTIQ_LOG_LEVEL="INFO"
```

### Development

```bash
# Start frontend development server
cd detectiq/webapp/frontend
npm run dev

# Start backend development server
poetry run python -m detectiq.webapp.backend
```

## Project Structure

```
DetectIQ/
├── detectiq/
│   ├── core/                 # Core functionality
│   ├── licenses/            # License files
│   ├── llm/                 # LLM integration
│   │   ├── agents/         # LangChain agents
│   │   └── tools/          # Custom tools
│   └── webapp/             # Web application
│       ├── frontend/       # Next.js frontend
│       └── backend/        # FastAPI backend
├── tests/                  # Test suite
└── poetry.lock            # Dependency lock file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project uses multiple licenses:
- Core Project: LGPL v2.1
- Sigma Rules: Detection Rule License (DRL)
- YARA Rules: YARAForge License
- Snort Rules: GPL with VRT License

## Support & Community

- Join our [SigmaHQ Discord](https://discord.gg/27r98bMv6c) for discussions
- Report issues via GitHub Issues
- Follow development updates on [LinkedIn](https://www.linkedin.com/in/stephen-lincoln-52109065)

## Acknowledgments

- SigmaHQ Community
- YARA-Forge Contributors
- Snort Community
- OpenAI for GPT-4 Integration

