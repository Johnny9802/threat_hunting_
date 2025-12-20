# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-12-20

### Added
- GitHub Actions CI/CD pipeline
  - Automated testing on push/PR
  - Multi-OS testing (Ubuntu, macOS, Windows)
  - Multi-Python version support (3.10, 3.11, 3.12)
  - Code linting (Black, Flake8, isort, mypy)
  - Playbook schema validation
  - Security scanning (Safety, Bandit)
  - Package building and PyPI upload support
- Release automation workflow
- **5 New Playbooks:**
  - **T1021** - Lateral Movement via Remote Services (7 SPL, 10 KQL, 5 Sigma)
  - **T1547** - Boot/Logon Persistence (7 SPL, 12 KQL, 5 Sigma)
  - **T1486** - Ransomware Detection (8 SPL, 10 KQL, 5 Sigma)
  - **T1562** - Security Tool Tampering (5 SPL, 5 KQL, 2 Sigma)
  - **T1087** - Account Discovery (4 SPL, 4 KQL, 2 Sigma)

### Changed
- Updated README with all 8 playbooks
- Added CHANGELOG.md for version tracking
- Added TODO.md for development roadmap

### Total Coverage (v1.1)
- **8 complete playbooks** covering MITRE ATT&CK tactics:
  - Initial Access (T1566 - Phishing)
  - Execution (T1059 - Command Execution)
  - Persistence (T1547 - Autostart)
  - Credential Access (T1003 - Credential Dumping)
  - Discovery (T1087 - Account Discovery)
  - Lateral Movement (T1021 - Remote Services)
  - Defense Evasion (T1562 - Impair Defenses)
  - Impact (T1486 - Ransomware)
- **150+ detection queries** (31 SPL, 63 KQL, 26 Sigma)
- **CI/CD pipeline** for automated quality assurance

## [1.0.0] - 2025-12-20

### Added
- Initial release
- CLI tool with Click and Rich
- AI assistant integration (Groq/OpenAI)
- 3 complete playbooks:
  - PB-T1566-001: Phishing Email Detection
  - PB-T1059-001: Malicious Command Execution
  - PB-T1003-001: OS Credential Dumping
- Multi-SIEM support (Splunk, Elastic, Sigma)
- 50+ production-ready detection queries
- MITRE ATT&CK framework mapping
- Comprehensive test suite
- Full documentation (README, QUICKSTART, CONTRIBUTING)
- Schema validation for playbooks

### Features
- `hunt list` - List all playbooks
- `hunt search` - Search by keyword/technique/tactic/tag/severity
- `hunt show` - View detailed playbook with syntax highlighting
- `hunt export` - Export query for specific SIEM
- `hunt export-all` - Bulk export queries
- `hunt ai explain` - AI playbook explanation
- `hunt ai ask` - Ask security questions
- `hunt ai suggest` - Get investigation suggestions
- `hunt ai generate` - Generate query variants

[Unreleased]: https://github.com/Johnny9802/threat_hunting_/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Johnny9802/threat_hunting_/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Johnny9802/threat_hunting_/releases/tag/v1.0.0
