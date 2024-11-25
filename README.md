# DetectIQ

DetectIQ is an advanced detection engineering toolkit that leverages AI to assist in creating, translating, and managing detection rules across multiple security platforms. It uses LangChain and GPT-4o to provide intelligent assistance for YARA, Snort, and Sigma rules.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL_v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![Build Status](https://github.com/slincoln-aiq/DetectIQ/workflows/CI/badge.svg)](https://github.com/slincoln-aiq/DetectIQ/actions)
[![Code Coverage](https://codecov.io/gh/slincoln-aiq/DetectIQ/branch/main/graph/badge.svg)](https://codecov.io/gh/slincoln-aiq/DetectIQ)

## Table of Contents

- [DetectIQ](#detectiq)
  - [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
  - [Features \& Benefits](#features--benefits)
    - [Threat Detection](#threat-detection)
    - [Incident Response](#incident-response)
    - [Threat Hunting](#threat-hunting)
    - [Key Components](#key-components)
  - [Installation \& Setup](#installation--setup)
    - [Prerequisites](#prerequisites)
    - [Configuration](#configuration)
    - [Environment Setup](#environment-setup)
    - [Default Paths](#default-paths)
  - [Usage Guide](#usage-guide)
    - [Basic Examples](#basic-examples)
    - [Advanced Usage](#advanced-usage)
    - [Performance Tips](#performance-tips)
  - [Development](#development)
    - [Project Structure](#project-structure)
    - [Contributing](#contributing)
    - [Development Guidelines](#development-guidelines)
  - [Support \& Community](#support--community)
    - [Troubleshooting](#troubleshooting)
    - [Solutions](#solutions)
    - [Security Considerations](#security-considerations)
  - [Citation](#citation)
  - [Legal](#legal)
    - [License](#license)
    - [Code of Conduct](#code-of-conduct)
  - [Installation](#installation)
    - [Production Installation](#production-installation)

## Quick Start

```bash
# Install with poetry
poetry install

# Set up environment
export OPENAI_API_KEY="your-api-key"

# Run an example
poetry run python examples/llm_rule_translation_and_creation.py
```

## Features & Benefits

### Threat Detection

- Convert existing SIEM queries (KQL, SPL) to standardized Sigma rules
- Create YARA rules from malware samples or behavioral descriptions
- Generate Snort rules from PCAP analysis of malicious traffic
- Translate Sigma rules to various SIEM platforms (Splunk, Elastic, Microsoft XDR)

### Incident Response

- Quickly create detection rules from incident artifacts
- Convert IOCs into multiple detection formats
- Analyze malware samples and generate YARA rules
- Create network detection rules from captured attack traffic

### Threat Hunting

- Convert hunting queries into standardized detection rules
- Create multi-platform detections from threat intelligence
- Generate rules from observed adversary behaviors
- Translate successful hunting queries across different platforms

### Key Components

- **Vector Stores**: Maintains separate vector stores for each rule type
- **Rule Updaters**: YARA: Downloads and processes rules from yara-forge, Snort: Manages community ruleset updates, Sigma: Handles rule conversions and updates
- **Analysis Tools**: File Analysis: Deep inspection of files for YARA rules, PCAP Analysis: Network traffic analysis for Snort rules, Pattern Extraction: Identifies unique characteristics

## Installation & Setup

### Prerequisites

- Python 3.9 or higher

### Configuration

The following environment variables can be set:

- `OPENAI_API_KEY`: Required for AI functionality
- `DETECTIQ_RULE_DIR`: Custom rule directory location
- `DETECTIQ_VECTOR_STORE_DIR`: Custom vector store location
- `DETECTIQ_LOG_LEVEL`: Set logging verbosity
- `DETECTIQ_MODEL`: Specify OpenAI model to use

### Environment Setup

1. Copy `.env.example` to `.env`:   ```bash
   cp .env.example .env```

2. Add your API keys to `.env`
3. Never commit your `.env` file

### Default Paths

```python
DEFAULT_DIRS = {
    'YARA_RULE_DIR': 'detectiq/llm/data/yara/rules',
    'SNORT_RULE_DIR': 'detectiq/llm/data/snort/rules',
    'SIGMA_RULE_DIR': 'detectiq/llm/data/sigma/rules',
    'VECTOR_STORE_DIR': 'detectiq/llm/data/vectorstore'
}
```

## Usage Guide

### Basic Examples

#### 1. Sigma Rule Translation and Creation

```python
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.globals import DEFAULT_DIRS

# Initialize LLMs
agent_llm = ChatOpenAI(temperature=0, model="gpt-4o")
rule_creation_llm = ChatOpenAI(temperature=0, model="gpt-4o")

# Initialize Sigma LLM
sigma_llm = SigmaLLM(
    embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
    agent_llm=agent_llm,
    rule_creation_llm=rule_creation_llm,
    vector_store_dir=DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR
)

# Example 1: Translate a Sigma rule to Splunk
translate_input = """
Convert this Sigma rule to a Splunk query:
title: Suspicious Process Creation
detection:
    selection:
        CommandLine|contains: 'certutil.exe'
    condition: selection
"""

# Example 2: Create a new Sigma rule
create_input = """
Create a Sigma rule to detect potential credential dumping using reg.exe save command
"""
```

#### 2. YARA Rule Creation from File Analysis

```python
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.globals import DEFAULT_DIRS

# Initialize LLMs
agent_llm = ChatOpenAI(temperature=0, model="gpt-4o")
rule_creation_llm = ChatOpenAI(temperature=0, model="gpt-4o")

# Initialize YARA LLM
yara_llm = YaraLLM(
    embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
    agent_llm=agent_llm,
    rule_creation_llm=rule_creation_llm,
    rule_dir=DEFAULT_DIRS.YARA_RULE_DIR,
    vector_store_dir=DEFAULT_DIRS.YARA_VECTOR_STORE_DIR
)

# Example: Analyze file and create YARA rule
file_path = "/path/to/suspicious/file.exe"
analysis_input = f"Analyze this file and create a YARA rule to detect similar files: {file_path}"
```

#### 3. Snort Rule Creation from PCAP Analysis

```python
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.globals import DEFAULT_DIRS

# Initialize LLMs
agent_llm = ChatOpenAI(temperature=0, model="gpt-4o")
rule_creation_llm = ChatOpenAI(temperature=0, model="gpt-4o")

# Initialize Snort LLM
snort_llm = SnortLLM(
    embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
    agent_llm=agent_llm,
    rule_creation_llm=rule_creation_llm,
    rule_dir=DEFAULT_DIRS.SNORT_RULE_DIR,
    vector_store_dir=DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR
)

# Example: Analyze PCAP and create Snort rule
pcap_path = "/path/to/capture.pcap"
analysis_input = f"Analyze this PCAP file and create Snort rules to detect similar traffic patterns: {pcap_path}"
```

#### 4. Using the Vector Store

Each rule type (Sigma, YARA, Snort) maintains its own vector store for finding similar rules. The stores are automatically populated when rules are downloaded/created and are used to provide context for new rule creation.

```python
# Example: Load existing vector store
try:
    print("Loading existing vector store...")
    sigma_llm.load_vectordb()
except FileNotFoundError:
    print("Creating new vector store...")
    sigma_llm.create_vectordb(save=True)
```

#### 5. Rule Updates and Management

```python
# Update YARA rules
yara_llm.update_rules()  # Downloads latest rules from yara-forge

# Update Snort rules
snort_llm.update_rules()  # Downloads latest community rules
```

### Advanced Usage

- Provide detailed descriptions for better rules
- Use file/PCAP analysis for pattern-based rules
- Combine multiple detection techniques
- Leverage existing rules as templates

### Performance Tips

- Regular maintenance recommended
- Periodic reindexing for better performance
- Cleanup of outdated embeddings
- Optimal chunk size for indexing

## Development

### Project Structure

```plaintext
detectiq/
├── llm/
│   ├── base.py            # Base classes for rule handling
│   ├── sigma_rules.py     # Sigma rule implementation
│   ├── yara_rules.py      # YARA rule implementation
│   ├── snort_rules.py     # Snort rule implementation
│   ├── tools/             # Tool implementations
│   ├── toolkits/          # Toolkit implementations
│   └── utils/             # Utility functions and helpers
├── globals.py             # Global configurations
└── data/                  # Rule and vector store data
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Add tests for new features
- Update documentation as needed
- Use type hints
- Keep functions focused and modular

## Support & Community

- 📫 For bug reports and feature requests, please use [GitHub Issues](https://github.com/slincoln-aiq/DetectIQ/issues)
- 💬 For questions and discussions, join our [Discord Server](link) or [Discussions](link)
- 📖 Check out our [Wiki](link) for detailed documentation

### Troubleshooting

- Vector store dimension mismatch
- OpenAI API rate limits
- File permission issues
- Import resolution problems

### Solutions

- Recreate vector stores if dimensions change
- Implement rate limiting and retries
- Check directory permissions
- Verify Python path and imports

### Security Considerations

- Always review generated detection rules before deployment
- Keep your OpenAI API key secure and never commit it to version control
- Monitor API usage to prevent unexpected costs
- Consider running sensitive analysis in an isolated environment
- Validate all rules against test data before production deployment

## Citation

If you use DetectIQ in your research, please cite:

```bibtex
@software{detectiq2024,
  author = {Your Name},
  title = {DetectIQ: AI-Powered Detection Engineering Toolkit},
  year = {2024},
  url = {https://github.com/slincoln-aiq/DetectIQ}
}
```

## Legal

### License

This project is licensed under the LGPL-2.1-or-later License - see the LICENSE file for details.

### Code of Conduct

Please note that this project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Installation

### Production Installation
```bash
pip install .
```

