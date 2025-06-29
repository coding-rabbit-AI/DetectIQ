# DetectIQ
DetectIQ is an AI-powered security rule management platform that helps create, analyze, and optimize detection rules across multiple security platforms. It can be used with the provided UI, or just with Python scripts using the self contained `detectiq/core` module. See examples in the [examples](examples/) directory for more information.
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL_v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-red.svg)]()
- [Quickstart](#quickstart)
- [Current Features](#current-features)
- [Road Map](#road-map)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Support & Community](#support--community)
- [Acknowledgments](#acknowledgments)

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
> We welcome all feedback and contributions, but please use at your own risk!

## Quickstart
To get started, run the commands below. For more information, refer to the [docs](docs/README.md)!

**Step 1.** Clone the repository.
```bash
git clone https://github.com/slincoln-aiq/DetectIQ.git
```

**Step 2.** Set your environment variables (using [`.env.example`](.env.example) as a template).
```bash
cp .env.example .env
```

**Step 3.** Run the provided `start.sh` script and pass `install` as an argument.
```bash
bash start.sh install
```

**Step 4.** Run the provided `start.sh` script and pass `run` as an argument.
```bash
bash start.sh run
```

**Step 5.** Use your favorite browser to navigate to [http://localhost:3000](http://localhost:3000).

## Ollama(로컬/외부 LLM) 연동 사용법

DetectIQ는 OpenAI API 대신 Ollama API(로컬 또는 외부 서버)로도 동작할 수 있습니다.

### Ollama 서버 준비
1. [Ollama 공식 문서](https://ollama.com/)를 참고하여 서버를 설치 및 실행하세요.
2. 원하는 모델(예: llama2, mistral 등)을 다운로드하고 서버에 로드하세요.
   ```bash
   ollama pull llama2
   ollama serve # 또는 ollama run llama2
   ```
3. 서버가 외부에서 접근 가능하도록 방화벽/포트 설정을 확인하세요. (기본 포트: 11434)

### DetectIQ에서 Ollama 사용 설정
1. `.env` 또는 환경변수에 아래 항목을 추가/수정하세요:
   ```env
   LLM_MODEL=llama2
   OLLAMA_BASE_URL=http://<ollama-server-host>:11434
   LLM_PROVIDER=ollama
   ```
2. 별도의 OpenAI API Key는 필요하지 않습니다.
3. DetectIQ 내부 LLM 인스턴스 생성은 `detectiq/core/llm/base.py`의 `get_ollama_llm()` 함수를 통해 Ollama API를 사용합니다.

### 코드에서 Ollama LLM 사용 예시
```python
from detectiq.core.llm.base import get_ollama_llm
llm = get_ollama_llm(model="llama2", base_url="http://<ollama-server-host>:11434")
```

> Ollama 서버가 반드시 실행 중이어야 하며, 네트워크로 접근 가능해야 합니다.

## Current Features
### AI-Powered Detection 
- Create and optimize detection rules using OpenAI's LLM models
- Intelligent rule suggestions based on context and best practices
- Automated rule validation and testing 
- Upload malware samples and PCAP files for static analysis, automatically adding context for YARA and Snort rule creation
- LLM Rule creation analysis and detection logic returned in the rule creation response

### Rule Repository Integration 
- Enhanced by community-tested repositories:
  - SigmaHQ Core Ruleset
  - YARA-Forge Rules
  - Snort3 Community Ruleset
- Automatically check and update repositories with rule changes
- Vectorize rules for efficient similarity comparison for more context-aware rule creation engine

### Static Analysis Integration 
- Automated file analysis for YARA rules
- PCAP analysis for Snort rule creation
- Implicit log analysis for Sigma rule optimization (Explicit Analysis Coming Soon)

### Multi-Platform Integration 
- Automatic Sigma rule translation to various SIEM queries using `pySigma` and `SigmAIQ` wrapper
- Seamlessly create Splunk Enterprise Security correlation rules from Sigma rules

## Road Map
- [ ] Custom/local LLM models, embeddings, and vector stores
- [ ] More integrations with SIEMs such as Elastic and Microsoft XDR
- [ ] Explicit log analysis for Sigma rule optimization
- [ ] Rule testing and validation
- [ ] Rule searching, e.g. "Do I have a rule in place that can detect this?"
- [ ] Deployment tracking and workflow automation
- [ ] Rule management UI Enhancements
- [ ] Authentication and Authorization
- [ ] Project refactoring for production readiness
- [ ] Chatbot (langchain agents) UI with memory
- [ ] Docker containerization and deployment
- [ ] Rule management without OpenAI requirements
- [ ] More non-webapp examples

## Screenshots
### Rule Dashboard with Splunk Deployment Option
<p align="center">
  <em>Rule Dashboard with Splunk Deployment Option</em>
  <img src="docs/images/detectiq_rules_page.png" alt="Rule Dashboard with Splunk Deployment Option"/>
</p>

### Sigma Rule Creation
<p align="center">
  <em>Sigma Rule Creation from threat report snippet</em>
  <img src="docs/images/detectiq_sigma_rule_creation_1.png" alt="Sigma Rule Creation"/>
  <img src="docs/images/detectiq_sigma_rule_creation_2.png" alt="Sigma Rule Creation"/>
</p>

### YARA Rule Creation
<p align="center">
  <em>YARA Rule Creation using file analysis from uploaded mimikatz.exe sample</em>
  <img src="docs/images/detectiq_yara_rule_creation_file_1.png" alt="YARA Rule Creation"/>
  <img src="docs/images/detectiq_yara_rule_creation_file_2.png" alt="YARA Rule Creation"/>
</p>

### Settings Page
<p align="center">
  <em>Settings Page</em>
  <img src="docs/images/detectiq_settings.png" alt="Settings Page"/>
</p>

### About Page
<p align="center">
  <em>About Page</em>
  <img src="docs/images/detectiq_about.png" alt="About Page"/>
</p>

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

## Acknowledgments
- SigmaHQ Community
- YARA-Forge Contributors
- Snort Community
- OpenAI for GPT-4o Integration
