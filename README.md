# 🎯 Threat Hunting Playbook

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI/CD](https://github.com/Johnny9802/threat_hunting_/actions/workflows/ci.yml/badge.svg)](https://github.com/Johnny9802/threat_hunting_/actions/workflows/ci.yml)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Powered by AI](https://img.shields.io/badge/Powered%20by-AI-green.svg)](https://groq.com/)

> **AI-powered CLI tool for managing, searching, and analyzing threat hunting playbooks with real-time detection queries for Splunk, Elastic, and Sigma.**

## 📋 Overview

The Threat Hunting Playbook is a production-ready CLI tool designed for security analysts, threat hunters, and SOC teams. It provides:

- **🔍 Advanced Search**: Find playbooks by technique, tactic, tag, or keyword
- **🤖 AI Assistant**: Get AI-powered explanations, generate query variants, and receive investigation suggestions
- **📊 Multi-SIEM Support**: Export queries for Splunk (SPL), Elastic (KQL), and Sigma
- **🎨 Rich Terminal UI**: Beautiful, color-coded output with syntax highlighting
- **🏗️ MITRE ATT&CK Mapped**: All playbooks mapped to MITRE ATT&CK framework
- **⚡ Production-Ready**: Real, tested detection queries ready to deploy

## ✨ Features

### Core Functionality
- **Playbook Management**: Browse, search, and view detailed threat hunting playbooks
- **Query Export**: Export detection queries in multiple SIEM formats
- **MITRE Integration**: Automatic MITRE ATT&CK technique and tactic mapping
- **Validation**: JSON schema validation for all playbooks

### AI-Powered Features (requires API key)
- **Explain Playbooks**: Get detailed explanations of attack techniques and detection logic
- **Ask Questions**: Free-form questions to the AI security expert
- **Investigation Suggestions**: Get next steps when you find suspicious activity
- **Generate Variants**: Adapt playbooks to different environments (Azure AD, Linux, etc.)

### Included Playbooks (8 Complete)
1. **PB-T1566-001**: Phishing Email Detection (T1566 - Initial Access)
2. **PB-T1059-001**: Malicious Command Execution (T1059 - Execution)
3. **PB-T1003-001**: OS Credential Dumping (T1003 - Credential Access)
4. **PB-T1021-001**: Lateral Movement via Remote Services (T1021 - Lateral Movement)
5. **PB-T1547-001**: Boot/Logon Persistence (T1547 - Persistence)
6. **PB-T1486-001**: Ransomware Detection (T1486 - Impact)
7. **PB-T1562-001**: Security Tool Tampering (T1562 - Defense Evasion)
8. **PB-T1087-001**: Account Discovery (T1087 - Discovery)

Each playbook includes:
- Complete YAML metadata with MITRE mapping
- Real, production-ready queries for Splunk, Elastic, and Sigma
- Investigation steps and false positive guidance
- IOCs and references

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/threat-hunting-playbook.git
cd threat-hunting-playbook

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Basic Setup

```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your API key (optional, for AI features)
# Get free Groq API key at: https://console.groq.com/keys
nano .env
```

### First Commands

```bash
# List all playbooks
hunt list

# Search for phishing playbooks
hunt search phishing

# View a specific playbook
hunt show PB-T1566-001

# Export a query for Splunk
hunt export PB-T1566-001 --siem splunk
```

## 📖 Usage Guide

### Searching Playbooks

```bash
# Free-text search
hunt search "credential dumping"

# Search by MITRE technique
hunt search --technique T1566

# Search by tactic
hunt search --tactic initial-access

# Search by tag
hunt search --tag powershell

# Search by severity
hunt search --severity critical

# Combine filters
hunt search --tactic execution --severity high
```

### Viewing Playbooks

```bash
# Show detailed playbook with syntax-highlighted queries
hunt show PB-T1566-001

# Export as JSON
hunt show PB-T1566-001 --format json
```

### Exporting Queries

```bash
# Export single query to stdout
hunt export PB-T1566-001 --siem splunk

# Export to file
hunt export PB-T1566-001 --siem elastic --output phishing.kql

# Export all queries for a playbook
hunt export-all PB-T1566-001 --output ./exports

# Export all playbooks for a specific SIEM
hunt export-all --siem sigma --output ./sigma-rules
```

### AI Assistant Commands

**Prerequisites**: Set `GROQ_API_KEY` or `OPENAI_API_KEY` in `.env` file

```bash
# Explain a playbook in detail
hunt ai explain PB-T1566-001

# Ask a security question
hunt ai ask "How do I detect mimikatz in Splunk?"

# Get investigation suggestions
hunt ai suggest --found "User executed suspicious PowerShell with base64 encoding"

# Generate a variant for different environment
hunt ai generate PB-T1566-001 --target "Azure AD" --siem elastic
```

## 🎨 Example Output

### List Playbooks
```
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ ID            ┃ Name                               ┃ Technique ┃ Tactic            ┃ Severity ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ PB-T1003-001  │ OS Credential Dumping Detection    │ T1003     │ credential-access │ CRITICAL │
│ PB-T1059-001  │ Malicious Command Execution        │ T1059     │ execution         │ HIGH     │
│ PB-T1566-001  │ Phishing Email Detection           │ T1566     │ initial-access    │ HIGH     │
└───────────────┴────────────────────────────────────┴───────────┴───────────────────┴──────────┘
```

### Show Playbook
```
╭─────────────────────────── PB-T1566-001 ───────────────────────────╮
│ Phishing Email Detection and Analysis                             │
│ Detect and investigate phishing emails with malicious attachments │
╰────────────────────────────────────────────────────────────────────╯

Metadata
  MITRE Technique  T1566 - Phishing (initial-access)
  Severity         HIGH
  Author           Threat Hunting Team
  Created          2024-01-15

Hunt Hypothesis
╭────────────────────────────────────────────────────────────────────╮
│ Adversaries frequently use phishing as an initial access vector... │
╰────────────────────────────────────────────────────────────────────╯

Detection Queries
[Syntax-highlighted queries displayed here]
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Groq API (recommended - free tier available)
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.1-70b-versatile

# OpenAI API (fallback)
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4-turbo-preview

# Default provider
AI_PROVIDER=groq  # or openai
```

### Getting API Keys

#### Groq (Recommended - Free)
1. Visit https://console.groq.com/keys
2. Sign up for a free account
3. Create an API key
4. Add to `.env` as `GROQ_API_KEY`

#### OpenAI (Paid)
1. Visit https://platform.openai.com/api-keys
2. Create an API key
3. Add to `.env` as `OPENAI_API_KEY`

## 📁 Project Structure

```
threat-hunting-playbook/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup
├── .env.example                 # Environment template
├── .gitignore                   # Git ignore rules
├── playbooks/
│   ├── schema.json              # Playbook validation schema
│   └── techniques/
│       ├── T1566-phishing/
│       │   ├── playbook.yaml    # Playbook metadata
│       │   └── queries/
│       │       ├── splunk.spl   # Splunk query
│       │       ├── elastic.kql  # Elastic query
│       │       └── sigma.yml    # Sigma rules
│       ├── T1059-command-execution/
│       │   ├── playbook.yaml
│       │   └── queries/
│       └── T1003-credential-dumping/
│           ├── playbook.yaml
│           └── queries/
├── src/
│   ├── __init__.py
│   ├── cli.py                   # CLI interface (click + rich)
│   ├── parser.py                # YAML playbook parser
│   ├── search.py                # Search functionality
│   ├── exporter.py              # Query export module
│   ├── ai_assistant.py          # AI integration (Groq/OpenAI)
│   └── mitre_mapping.py         # MITRE ATT&CK utilities
└── tests/
    ├── test_parser.py
    ├── test_search.py
    └── test_ai.py
```

## 🤝 Contributing

We welcome contributions! Here's how to add a new playbook:

### 1. Create Playbook Directory

```bash
mkdir -p playbooks/techniques/TXXXX-technique-name/queries
```

### 2. Create `playbook.yaml`

Follow the schema in `playbooks/schema.json`:

```yaml
id: PB-TXXXX-001
name: "Your Playbook Name"
description: "Brief description"

mitre:
  technique: TXXXX
  tactic: tactic-name
  subtechniques: [TXXXX.001]

severity: high|medium|low|critical
author: Your Name
created: YYYY-MM-DD
updated: YYYY-MM-DD

data_sources:
  - Required log sources

hunt_hypothesis: |
  Detailed narrative about what you're hunting for...

queries:
  splunk: queries/splunk.spl
  elastic: queries/elastic.kql
  sigma: queries/sigma.yml

investigation_steps:
  - Step 1
  - Step 2

false_positives:
  - Possible FP 1

tags: [tag1, tag2]
```

### 3. Add Queries

Create query files in `queries/` subdirectory:
- `splunk.spl` - Splunk SPL queries
- `elastic.kql` - Elastic KQL queries
- `sigma.yml` - Sigma rules

### 4. Validate

```bash
# Test that your playbook loads correctly
hunt show PB-TXXXX-001
```

### 5. Submit Pull Request

1. Fork the repository
2. Create a feature branch
3. Add your playbook
4. Submit PR with description

## 🧪 Testing

```bash
# Run tests
pytest tests/

# Run specific test
pytest tests/test_parser.py

# Run with coverage
pytest --cov=src tests/
```

## 🛣️ Roadmap

- [ ] **Advanced Features**
  - [ ] Query validation and testing framework
  - [ ] Integration with MITRE ATT&CK Navigator
  - [ ] Playbook versioning and change tracking
  - [ ] Custom playbook templates

- [ ] **More Playbooks**
  - [ ] Lateral Movement (T1021)
  - [ ] Persistence Mechanisms (T1547)
  - [ ] Defense Evasion (T1562)
  - [ ] Collection (T1560)
  - [ ] Exfiltration (T1041)

- [ ] **Integrations**
  - [ ] Direct SIEM API integration (auto-deploy queries)
  - [ ] Threat intelligence feed integration
  - [ ] SOAR platform connectors
  - [ ] Ticketing system integration

- [ ] **UI Enhancements**
  - [ ] Web dashboard
  - [ ] Playbook dependency graphs
  - [ ] Timeline visualization
  - [ ] Interactive query builder

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **MITRE ATT&CK** - Framework and technique definitions
- **Sigma Project** - Detection rule format
- **Splunk** & **Elastic** - SIEM platforms
- **Groq** - Fast AI inference
- **Click** & **Rich** - CLI framework and terminal formatting

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/threat-hunting-playbook/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/threat-hunting-playbook/discussions)
- **Email**: security@example.com

## ⚠️ Disclaimer

This tool is provided for legitimate security research, threat hunting, and defensive security operations. Always ensure you have proper authorization before deploying detection queries in production environments. The authors are not responsible for misuse or damage caused by this tool.

---

**Built with ❤️ by the Threat Hunting Community**

*Happy Hunting! 🎯*
