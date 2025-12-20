# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added v1.1 (In Progress)
- GitHub Actions CI/CD pipeline
  - Automated testing on push/PR
  - Multi-OS testing (Ubuntu, macOS, Windows)
  - Multi-Python version support (3.10, 3.11, 3.12)
  - Code linting (Black, Flake8, isort, mypy)
  - Playbook schema validation
  - Security scanning (Safety, Bandit)
  - Package building and PyPI upload support
- Release automation workflow
- New playbook: T1021 - Lateral Movement via Remote Services
  - Complete Splunk SPL queries (7 queries)
  - Elastic KQL queries (10 queries)
  - Sigma rules (5 rules)
  - Comprehensive detection for RDP, SMB, WinRM, PSExec, Pass-the-Hash

### Planned for v1.1
- [ ] 4 additional playbooks (T1547, T1562, T1087, T1486)
- [ ] Query validation framework
- [ ] Enhanced export (JSON/CSV/templates)
- [ ] Performance benchmarking
- [ ] Updated documentation

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

[Unreleased]: https://github.com/Johnny9802/threat_hunting_/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Johnny9802/threat_hunting_/releases/tag/v1.0.0
