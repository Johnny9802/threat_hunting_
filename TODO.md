# TODO - v1.1 Development

## ✅ Completed

- [x] GitHub Actions CI/CD pipeline
  - [x] Automated testing (multi-OS, multi-Python)
  - [x] Linting and type checking
  - [x] Playbook validation
  - [x] Security scanning
  - [x] Release automation
- [x] New playbook: T1021 - Lateral Movement
  - [x] Complete YAML metadata
  - [x] Splunk queries (7 comprehensive queries)
  - [x] Elastic queries (10 queries)
  - [x] Sigma rules (5 rules)

## 🚧 In Progress

### New Playbooks (4 remaining)

#### T1547 - Boot/Logon Persistence
- [x] YAML metadata created
- [ ] Splunk queries (need 5-7 queries)
- [ ] Elastic queries (need 8-10 queries)
- [ ] Sigma rules (need 4-5 rules)

**Detection focus:**
- Registry run keys (HKCU/HKLM Run)
- Startup folder modifications
- Scheduled task creation/modification
- WMI event subscriptions
- Service creation

#### T1562 - Impair Defenses
- [ ] YAML metadata
- [ ] Splunk queries
- [ ] Elastic queries
- [ ] Sigma rules

**Detection focus:**
- Antivirus/EDR tampering
- Windows Defender disabling
- Firewall rule modifications
- Event log clearing
- Security tool process termination

#### T1087 - Account Discovery
- [ ] YAML metadata
- [ ] Splunk queries
- [ ] Elastic queries
- [ ] Sigma rules

**Detection focus:**
- net user/group enumeration
- LDAP queries
- PowerView usage
- BloodHound data collection
- Active Directory reconnaissance

#### T1486 - Data Encrypted for Impact (Ransomware)
- [ ] YAML metadata
- [ ] Splunk queries
- [ ] Elastic queries
- [ ] Sigma rules

**Detection focus:**
- Rapid file encryption patterns
- Shadow copy deletion
- Backup deletion
- Ransomware note creation
- Volume encryption activity

## 📋 Additional v1.1 Features

### Query Validation Framework
- [ ] Create `src/validator.py` module
- [ ] Splunk SPL syntax validator
- [ ] Elastic KQL syntax validator
- [ ] Sigma rule validator (use official sigma tools)
- [ ] Add validation to CLI: `hunt validate PLAYBOOK_ID`
- [ ] Integration with CI/CD tests

### Enhanced Export
- [ ] JSON export format
- [ ] CSV export format for IOCs
- [ ] Alert template generation (Splunk/Elastic)
- [ ] Bulk export improvements
- [ ] Export statistics/summary

### Performance Benchmarking
- [ ] Create `src/benchmark.py`
- [ ] Measure parser performance
- [ ] Measure search performance
- [ ] Add `hunt benchmark` command
- [ ] Performance regression tests

### Documentation Updates
- [ ] Update README with new playbooks
- [ ] Add CI/CD badge to README
- [ ] Update CONTRIBUTING with CI/CD workflow
- [ ] Add troubleshooting section
- [ ] Video demo/screenshots

## 🎯 Quick Wins (Can do anytime)

- [ ] Add more tags to existing playbooks
- [ ] Add more IOCs to playbooks
- [ ] Add more references/links
- [ ] Improve error messages
- [ ] Add progress bars for long operations
- [ ] Add `hunt stats` command (show statistics)
- [ ] Add `hunt validate-all` command

## 🚀 Ready for v2.0 (After v1.1)

- [ ] Docker containerization
- [ ] FastAPI REST API
- [ ] Database integration (PostgreSQL)
- [ ] Redis caching
- [ ] docker-compose setup
- [ ] API documentation (Swagger)

## 📝 Notes

### Time Estimates
- Each playbook (complete): ~30-45 minutes
- Query validation framework: ~2 hours
- Enhanced export: ~1-2 hours
- Benchmarking: ~1 hour
- Documentation: ~30 minutes

### Priority Order
1. Complete remaining 4 playbooks (highest value)
2. Enhanced export (user-requested feature)
3. Query validation (quality assurance)
4. Benchmarking (nice to have)
5. Documentation updates (continuous)

### Dependencies
- Query validation requires understanding of each SIEM's query language
- Export enhancements need template design
- Benchmarking needs representative test data

---

**Last Updated**: 2025-12-20
**Current Version**: 1.0.0
**Target Version**: 1.1.0
**Estimated Completion**: 1-2 weeks
