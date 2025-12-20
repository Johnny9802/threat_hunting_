import { useState } from 'react';
import {
  FileText,
  Download,
  Copy,
  CheckCircle,
  Info,
  AlertCircle,
  Users,
  Target,
  TrendingUp,
  Shield,
  Book,
  HelpCircle,
  X,
} from 'lucide-react';
import { cn, copyToClipboard, downloadText } from '../lib/utils';

interface Template {
  id: string;
  name: string;
  description: string;
  useCase: string;
  content: string;
}

const TEMPLATES: Template[] = [
  {
    id: 'soc-rapid',
    name: 'SOC Rapid Post-Mortem',
    description: 'Quick format for time-sensitive SOC incidents',
    useCase: 'Daily SOC operations, minor to moderate incidents',
    content: `# Security Incident Post-Mortem - [INCIDENT ID]

**Date**: [DATE]
**Severity**: [Critical/High/Medium/Low]
**Incident Lead**: [NAME]
**Participants**: [NAMES]

## Executive Summary
[Brief 2-3 sentence overview of what happened]

## Timeline
- **[TIME]** - First detection
- **[TIME]** - Incident declared
- **[TIME]** - Containment achieved
- **[TIME]** - Incident resolved

## What Happened (Detection & Analysis)
[Describe how the incident was detected and what was discovered]

## Root Cause Analysis - The 5 Whys

### 1. Why did the incident occur?
**Answer**: [Your answer]

### 2. Why did our controls fail to prevent it?
**Answer**: [Your answer]

### 3. Why was the problem not detected earlier?
**Answer**: [Your answer]

### 4. Why did our process allow this condition?
**Answer**: [Your answer]

### 5. Why didn't we have adequate mitigations in place?
**Answer**: [Your answer]

## Response Actions Taken
### Containment
- [Action 1]
- [Action 2]

### Eradication
- [Action 1]
- [Action 2]

### Recovery
- [Action 1]
- [Action 2]

## What Went Well
- [Item 1]
- [Item 2]
- [Item 3]

## What Could Be Improved
- [Item 1]
- [Item 2]
- [Item 3]

## Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| [Action 1] | [Name] | [Date] | Open |
| [Action 2] | [Name] | [Date] | Open |

## Detection & Prevention Improvements
- [ ] Update detection rules: [Details]
- [ ] Enhance monitoring: [Details]
- [ ] Update runbooks: [Details]

## Lessons Learned
[Key takeaways for the team and organization]

---
*Remember: This is a blameless post-mortem. Focus on systems and processes, not individuals.*`,
  },
  {
    id: 'enterprise-comprehensive',
    name: 'Enterprise Comprehensive Post-Mortem',
    description: 'Detailed format for major incidents requiring executive reporting',
    useCase: 'Critical incidents, data breaches, major outages',
    content: `# SECURITY INCIDENT POST-MORTEM REPORT
## [INCIDENT NAME/ID]

**Classification**: [Public/Internal/Confidential]
**Date of Incident**: [DATE]
**Report Date**: [DATE]
**Severity**: [Critical/High/Medium/Low]
**Business Impact**: [High/Medium/Low]

---

## Executive Summary

**What Happened**: [2-3 sentences]

**Business Impact**: [Describe impact on business operations, customers, data, etc.]

**Root Cause**: [One sentence summary]

**Resolution**: [Current status and resolution]

**Key Lessons**: [Top 3 bullet points]

---

## Incident Details

### Classification
- **Incident ID**: [ID]
- **Category**: [Malware/Phishing/Data Breach/DDoS/Unauthorized Access/Other]
- **MITRE ATT&CK Techniques**: [T1XXX, T1YYY]
- **Affected Systems**: [List critical systems]
- **Data Classification**: [Public/Internal/Confidential/Restricted]

### Timeline

| Time (UTC) | Event | Actor/System |
|------------|-------|--------------|
| [TIME] | Initial compromise/detection | [SOURCE] |
| [TIME] | Alert triggered | [SYSTEM] |
| [TIME] | Investigation started | [TEAM] |
| [TIME] | Incident declared | [INCIDENT COMMANDER] |
| [TIME] | Containment initiated | [TEAM] |
| [TIME] | Containment achieved | [TEAM] |
| [TIME] | Eradication completed | [TEAM] |
| [TIME] | Recovery initiated | [TEAM] |
| [TIME] | Services restored | [TEAM] |
| [TIME] | Incident closed | [INCIDENT COMMANDER] |

---

## Detection & Analysis

### How We Detected It
[Describe detection method: automated alert, user report, threat intel, etc.]

### Initial Assessment
[First observations and triage]

### Investigation Findings
[Detailed findings from investigation]

### Indicators of Compromise (IOCs)
- **IPs**: [List]
- **Domains**: [List]
- **File Hashes**: [List]
- **Email Addresses**: [List]
- **Other**: [List]

---

## Root Cause Analysis - The 5 Whys

**Important**: This analysis focuses on system failures, not individual performance. We seek to understand what allowed the incident to occur and what prevented earlier detection or mitigation.

### 1. Why did this security incident occur?
**Answer**: [Describe the immediate technical or procedural cause]

**Supporting Evidence**: [Logs, screenshots, data points]

### 2. Why did our existing security controls fail to prevent this?
**Answer**: [Analyze why prevention controls didn't work]

**Controls Evaluated**:
- [Control 1]: [Why it didn't prevent the incident]
- [Control 2]: [Why it didn't prevent the incident]

### 3. Why was this incident not detected earlier in the attack lifecycle?
**Answer**: [Analyze detection gaps]

**Detection Opportunities Missed**:
- [Stage 1]: [What we could have detected]
- [Stage 2]: [What we could have detected]

### 4. Why did our processes and procedures allow this condition to exist?
**Answer**: [Analyze process gaps]

**Process Gaps**:
- [Process 1]: [Gap identified]
- [Process 2]: [Gap identified]

### 5. Why didn't we have adequate mitigations or compensating controls?
**Answer**: [Analyze strategic security gaps]

**Strategic Considerations**:
- [Consideration 1]
- [Consideration 2]

---

## Response Actions

### Containment
**Objective**: Limit the spread and impact of the incident

**Actions Taken**:
1. [Action 1 with timestamp and result]
2. [Action 2 with timestamp and result]
3. [Action 3 with timestamp and result]

**Effectiveness**: [Rate 1-10 and explain]

### Eradication
**Objective**: Remove the threat from the environment

**Actions Taken**:
1. [Action 1 with verification method]
2. [Action 2 with verification method]
3. [Action 3 with verification method]

**Verification**: [How we confirmed threat removal]

### Recovery
**Objective**: Restore systems and services to normal operations

**Actions Taken**:
1. [Action 1 with completion timestamp]
2. [Action 2 with completion timestamp]
3. [Action 3 with completion timestamp]

**Monitoring**: [Enhanced monitoring implemented]

---

## Impact Assessment

### Business Impact
- **Revenue Impact**: [$ amount or N/A]
- **Customers Affected**: [Number]
- **Data Compromised**: [Yes/No and details]
- **Operational Downtime**: [Hours]
- **Regulatory Implications**: [GDPR/HIPAA/PCI-DSS/etc.]

### Technical Impact
- **Systems Compromised**: [Number and list]
- **Accounts Compromised**: [Number]
- **Data Exfiltrated**: [Size and classification]

### Reputational Impact
- **Media Coverage**: [Yes/No]
- **Customer Notifications Required**: [Yes/No - Number]
- **Regulatory Reporting Required**: [Yes/No - Which agencies]

---

## What Went Well ✅

1. **[Success 1]**
   - [Why it worked well]
   - [Impact it had]

2. **[Success 2]**
   - [Why it worked well]
   - [Impact it had]

3. **[Success 3]**
   - [Why it worked well]
   - [Impact it had]

---

## What Could Be Improved 🔄

1. **[Improvement Area 1]**
   - **Current State**: [Description]
   - **Desired State**: [Description]
   - **Gap**: [What needs to change]

2. **[Improvement Area 2]**
   - **Current State**: [Description]
   - **Desired State**: [Description]
   - **Gap**: [What needs to change]

3. **[Improvement Area 3]**
   - **Current State**: [Description]
   - **Desired State**: [Description]
   - **Gap**: [What needs to change]

---

## Corrective Actions

| Priority | Category | Action | Owner | Due Date | Status | Verification |
|----------|----------|--------|-------|----------|--------|--------------|
| P0 | Detection | [Action] | [Name] | [Date] | [Status] | [How to verify] |
| P1 | Prevention | [Action] | [Name] | [Date] | [Status] | [How to verify] |
| P1 | Process | [Action] | [Name] | [Date] | [Status] | [How to verify] |
| P2 | Training | [Action] | [Name] | [Date] | [Status] | [How to verify] |

**Priority Definitions**:
- **P0**: Critical - Must be completed within 1 week
- **P1**: High - Must be completed within 1 month
- **P2**: Medium - Must be completed within 3 months
- **P3**: Low - To be scheduled

---

## Technical Improvements

### Detection Enhancements
- [ ] **Detection Rule Updates**
  - [Rule 1]: [Description]
  - [Rule 2]: [Description]

- [ ] **New Detection Coverage**
  - [MITRE Technique]: [New detection]
  - [Attack Pattern]: [New detection]

### Prevention Measures
- [ ] **Security Controls**
  - [Control 1]: [Implementation plan]
  - [Control 2]: [Implementation plan]

- [ ] **Configuration Changes**
  - [System 1]: [Change required]
  - [System 2]: [Change required]

### Response Improvements
- [ ] **Playbook Updates**
  - [Playbook 1]: [Updates needed]
  - [Runbook 1]: [Updates needed]

- [ ] **Tools & Automation**
  - [Tool 1]: [Enhancement]
  - [Automation 1]: [New capability]

---

## Lessons Learned

### For Security Team
1. [Lesson 1]
2. [Lesson 2]
3. [Lesson 3]

### For Engineering Team
1. [Lesson 1]
2. [Lesson 2]
3. [Lesson 3]

### For Organization
1. [Lesson 1]
2. [Lesson 2]
3. [Lesson 3]

---

## Follow-up Items

### 30-Day Review
- [ ] Verify all P0 actions completed
- [ ] Re-test detection for this attack pattern
- [ ] Verify all affected systems still clean
- [ ] Review action item progress

### 90-Day Review
- [ ] Verify all P1 actions completed
- [ ] Conduct table-top exercise for similar scenarios
- [ ] Update incident response plan
- [ ] Knowledge sharing session completed

---

## Appendices

### Appendix A: Technical Details
[Detailed technical information, logs, screenshots]

### Appendix B: Communication Log
[Record of internal and external communications]

### Appendix C: Cost Analysis
[Detailed breakdown of incident costs]

### Appendix D: Compliance
[Regulatory notifications and compliance impact]

---

**Document Control**
- **Version**: 1.0
- **Author**: [Name]
- **Reviewers**: [Names]
- **Approval**: [Name, Title]
- **Distribution**: [List recipients]

---

*This document follows blameless post-mortem principles. Its purpose is organizational learning and continuous improvement, not attribution of fault.*`,
  },
  {
    id: 'recurring-incident',
    name: 'Recurring Incident Analysis',
    description: 'Template for analyzing patterns in repeated incidents',
    useCase: 'Similar incidents occurring multiple times',
    content: `# Recurring Incident Pattern Analysis

**Incident Pattern**: [NAME]
**Date Range**: [START] to [END]
**Occurrences**: [NUMBER]
**Analyst**: [NAME]

## Incident Summary Table

| Date | Incident ID | Severity | Root Cause | Time to Resolve |
|------|-------------|----------|------------|-----------------|
| [DATE] | [ID] | [SEV] | [CAUSE] | [TIME] |
| [DATE] | [ID] | [SEV] | [CAUSE] | [TIME] |
| [DATE] | [ID] | [SEV] | [CAUSE] | [TIME] |

## Pattern Analysis

### Common Elements
**What is consistent across all occurrences?**
- [Element 1]
- [Element 2]
- [Element 3]

### Variations
**What differs between occurrences?**
- [Variation 1]
- [Variation 2]

### Trigger Events
**What typically initiates these incidents?**
- [Trigger 1]
- [Trigger 2]

## Root Cause Analysis (Deep Dive)

### Technical Root Cause
[Underlying technical issue that keeps allowing this to happen]

### Process Root Cause
[Process gaps that allow recurrence]

### Cultural/Organizational Root Cause
[Organizational factors contributing to recurrence]

## The 5 Whys (Applied to the Pattern)

### 1. Why does this incident keep recurring?
**Answer**: [Your analysis]

### 2. Why haven't our previous fixes been effective?
**Answer**: [Your analysis]

### 3. Why don't we detect this earlier each time?
**Answer**: [Your analysis]

### 4. Why does our process allow this pattern to continue?
**Answer**: [Your analysis]

### 5. Why haven't we prioritized a permanent solution?
**Answer**: [Your analysis]

## Previous Mitigation Attempts

| Date | Mitigation Attempted | Result | Why It Failed |
|------|---------------------|--------|---------------|
| [DATE] | [ACTION] | [RESULT] | [REASON] |
| [DATE] | [ACTION] | [RESULT] | [REASON] |

## True Root Cause
[After analysis, what is the actual underlying cause?]

## Permanent Solution Proposal

### Short-term (Immediate)
- [ ] [Action 1]
- [ ] [Action 2]

### Medium-term (1-3 months)
- [ ] [Action 1]
- [ ] [Action 2]

### Long-term (Strategic)
- [ ] [Action 1]
- [ ] [Action 2]

## Success Metrics
**How will we know this is truly resolved?**
- [Metric 1]: [Target]
- [Metric 2]: [Target]
- [Metric 3]: [Target]

## Stakeholder Buy-in
[Who needs to approve/support the solution and why]

---
*This analysis aims to break the cycle of recurring incidents through systematic root cause elimination.*`,
  },
  {
    id: 'compliance-focused',
    name: 'Compliance-Focused Post-Mortem',
    description: 'Template emphasizing regulatory and compliance requirements',
    useCase: 'Incidents requiring regulatory notification (GDPR, HIPAA, PCI-DSS)',
    content: `# Compliance-Focused Security Incident Report

**Incident ID**: [ID]
**Report Date**: [DATE]
**Reporting Period**: [PERIOD]
**Classification**: [Confidential]
**Regulatory Framework**: [GDPR/HIPAA/PCI-DSS/SOX/Other]

---

## Executive Summary for Compliance

**Incident Nature**: [Breach/Near-Miss/Policy Violation]
**Data Classification**: [PII/PHI/PCI/Other]
**Records Affected**: [NUMBER]
**Notification Required**: [Yes/No]
**Notification Deadline**: [DATE if applicable]
**Regulatory Risk**: [High/Medium/Low]

---

## Incident Classification

### Regulatory Scope
- [ ] GDPR (EU/EEA Personal Data)
- [ ] HIPAA (Protected Health Information)
- [ ] PCI-DSS (Cardholder Data)
- [ ] SOX (Financial Reporting)
- [ ] State Data Breach Laws: [Specify]
- [ ] Other: [Specify]

### Data Breach Determination
**Is this a reportable data breach under applicable regulations?**

**Decision**: [Yes/No]

**Justification**: [Legal and technical reasoning]

**Legal Review**: [Attorney name and date]

---

## Data Impact Assessment

### Data Elements Affected
| Data Type | Classification | # Records | Regulatory Impact |
|-----------|---------------|-----------|-------------------|
| [Type] | [Class] | [#] | [Impact] |
| [Type] | [Class] | [#] | [Impact] |

### Individuals Affected
- **Total Count**: [NUMBER]
- **Affected Jurisdictions**: [List states/countries]
- **Vulnerable Populations**: [Children, elderly, medical patients, etc.]

---

## Incident Timeline (for Regulatory Reporting)

| Date/Time (UTC) | Event | Compliance Relevance |
|-----------------|-------|---------------------|
| [TIME] | Discovery | Starts breach notification clock |
| [TIME] | Assessment completed | Breach determination made |
| [TIME] | Containment | Risk mitigation initiated |
| [TIME] | Notification prepared | Compliance requirement met |

---

## Root Cause Analysis

### The 5 Whys (Compliance-Focused)

#### 1. Why did this data security incident occur?
**Answer**: [Focus on control failures]

#### 2. Why did our compliance controls fail to prevent it?
**Answer**: [Analyze control effectiveness]

#### 3. Why was the breach not detected by compliance monitoring?
**Answer**: [Analyze monitoring gaps]

#### 4. Why didn't our policies and procedures prevent this?
**Answer**: [Policy effectiveness analysis]

#### 5. Why weren't compensating controls adequate?
**Answer**: [Control framework analysis]

---

## Regulatory Obligations

### Notification Requirements

#### Regulatory Authority Notification
- **Authority**: [Name of regulator]
- **Deadline**: [72 hours/30 days/other]
- **Status**: [Complete/In Progress/Not Required]
- **Notification Date**: [DATE]
- **Reference Number**: [#]

#### Individual Notification
- **Required**: [Yes/No]
- **Deadline**: [Timeframe]
- **Method**: [Email/Mail/Website]
- **Status**: [Complete/In Progress]
- **Completion Date**: [DATE]

#### Law Enforcement Notification
- **Required**: [Yes/No]
- **Agency**: [FBI/Secret Service/Local]
- **Status**: [Complete/In Progress]
- **Case Number**: [#]

### Documentation Requirements
- [ ] Incident log maintained
- [ ] Evidence preserved
- [ ] Chain of custody documented
- [ ] Legal hold initiated (if applicable)
- [ ] Records retention policy followed

---

## Compliance Impact Analysis

### Control Failures
| Control ID | Control Name | Expected Function | Actual Performance | Gap |
|------------|--------------|-------------------|-------------------|-----|
| [ID] | [NAME] | [EXPECTED] | [ACTUAL] | [GAP] |

### Policy Violations
| Policy | Violation | Impact | Remediation |
|--------|-----------|--------|-------------|
| [POLICY] | [VIOLATION] | [IMPACT] | [ACTION] |

### Audit Findings Relationship
[Were there prior audit findings related to this incident?]
- [Finding 1]: [Relationship]
- [Finding 2]: [Relationship]

---

## Regulatory Response Actions

### Immediate Compliance Actions
1. [Action] - Completed: [DATE]
2. [Action] - Completed: [DATE]
3. [Action] - Completed: [DATE]

### Corrective Action Plan (CAP)

| CAP ID | Finding | Corrective Action | Owner | Due Date | Validation |
|--------|---------|-------------------|-------|----------|------------|
| [ID] | [Finding] | [Action] | [Name] | [Date] | [Method] |

### Control Enhancements

| Control Domain | Enhancement | Implementation Date | Validation Method |
|----------------|-------------|---------------------|-------------------|
| [Domain] | [Enhancement] | [Date] | [Method] |

---

## Lessons Learned (Compliance Perspective)

### Control Effectiveness
[Analysis of which controls worked and which didn't]

### Process Improvements
[Compliance process improvements identified]

### Training Needs
[Compliance training gaps identified]

---

## Follow-up and Validation

### 30-Day Follow-up
- [ ] Regulatory notifications completed
- [ ] Individual notifications completed
- [ ] Immediate corrective actions verified
- [ ] Compliance review scheduled

### 90-Day Follow-up
- [ ] All CAP items completed
- [ ] Control enhancements validated
- [ ] Training completed
- [ ] Independent audit scheduled

### Annual Review
- [ ] Include in annual compliance report
- [ ] Update risk assessment
- [ ] Incorporate into compliance testing

---

## Attestations

### Incident Commander Attestation
"I attest that this report accurately reflects the incident details and response actions."

**Name**: [NAME]
**Title**: [TITLE]
**Date**: [DATE]
**Signature**: _________________

### Compliance Officer Attestation
"I attest that all regulatory requirements have been identified and addressed."

**Name**: [NAME]
**Title**: [TITLE]
**Date**: [DATE]
**Signature**: _________________

### Legal Counsel Attestation
"I have reviewed this report for legal sufficiency and regulatory compliance."

**Name**: [NAME]
**Title**: [TITLE]
**Date**: [DATE]
**Signature**: _________________

---

**Document Retention**: [Retention period per regulatory requirement]
**Classification**: [Confidential - Legal Privilege where applicable]
**Distribution**: [Authorized recipients only]

---
*This document may be subject to legal privilege. Consult with legal counsel before distribution.*`,
  },
];

export default function PostMortem() {
  const [selectedTemplate, setSelectedTemplate] = useState<Template | null>(null);
  const [copied, setCopied] = useState(false);

  const handleCopy = async (content: string) => {
    try {
      await copyToClipboard(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleDownload = (template: Template) => {
    downloadText(template.content, `${template.id}-template.md`);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-100">Post-Incident Analysis Templates</h1>
        <p className="text-gray-400 mt-1">
          Blameless post-mortem templates for security incidents
        </p>
      </div>

      {/* Theory Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Blameless Culture */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="rounded-lg bg-blue-500/10 p-3">
              <Users className="h-6 w-6 text-blue-500" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-100">Blameless Post-Mortems</h2>
              <p className="text-sm text-gray-400">Why we focus on systems, not people</p>
            </div>
          </div>

          <div className="space-y-4 text-sm text-gray-300">
            <p>
              <strong className="text-cyan-400">Blameless culture</strong> means we focus on{' '}
              <em>what</em> happened and <em>why the system allowed it</em>, not{' '}
              <em>who</em> made a mistake.
            </p>

            <div className="rounded-lg bg-gray-800/50 p-4">
              <p className="font-semibold text-gray-100 mb-2">Benefits:</p>
              <ul className="space-y-1 text-xs">
                <li className="flex items-start gap-2">
                  <CheckCircle size={14} className="text-green-500 flex-shrink-0 mt-0.5" />
                  <span>Encourages honest reporting of incidents</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle size={14} className="text-green-500 flex-shrink-0 mt-0.5" />
                  <span>Reveals systemic issues that need fixing</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle size={14} className="text-green-500 flex-shrink-0 mt-0.5" />
                  <span>Builds psychological safety in teams</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle size={14} className="text-green-500 flex-shrink-0 mt-0.5" />
                  <span>Leads to better long-term security posture</span>
                </li>
              </ul>
            </div>

            <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/10 p-4">
              <div className="flex items-start gap-2">
                <AlertCircle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-yellow-300 mb-1">Remember:</p>
                  <p className="text-xs text-yellow-200/80">
                    Human error is inevitable. System design determines whether that error becomes
                    an incident. Good post-mortems improve the system to tolerate future errors.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* 5 Whys Method */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="rounded-lg bg-cyan-500/10 p-3">
              <HelpCircle className="h-6 w-6 text-cyan-500" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-100">The 5 Whys Method</h2>
              <p className="text-sm text-gray-400">Root cause analysis technique</p>
            </div>
          </div>

          <div className="space-y-4 text-sm text-gray-300">
            <p>
              The <strong className="text-cyan-400">5 Whys</strong> is a simple but powerful
              technique to find the root cause of problems by repeatedly asking "Why?"
            </p>

            <div className="rounded-lg bg-gray-800/50 p-4">
              <p className="font-semibold text-gray-100 mb-2">How it works:</p>
              <ol className="space-y-2 text-xs">
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                    1
                  </span>
                  <span>Start with the problem statement</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                    2
                  </span>
                  <span>Ask "Why did this happen?" and write the answer</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                    3
                  </span>
                  <span>Take that answer and ask "Why?" again</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                    4
                  </span>
                  <span>Continue for 5 iterations (or until root cause found)</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                    5
                  </span>
                  <span>The final answer should reveal the systemic root cause</span>
                </li>
              </ol>
            </div>

            <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 p-4">
              <div className="flex items-start gap-2">
                <Info className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-blue-300 mb-1">Pro Tip:</p>
                  <p className="text-xs text-blue-200/80">
                    The magic number isn't always 5. Sometimes you'll find the root cause in 3
                    whys, sometimes it takes 7. The goal is to get past surface-level symptoms to
                    the underlying systemic issue.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* The 5 Why Questions for Security Incidents */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="rounded-lg bg-purple-500/10 p-3">
            <Target className="h-6 w-6 text-purple-500" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-100">
              The 5 Why Questions for Security Incidents
            </h2>
            <p className="text-sm text-gray-400">Standard questions to guide your analysis</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            {
              number: 1,
              question: 'Why did this security incident occur?',
              focus: 'Immediate technical or procedural cause',
              example: 'Phishing email bypassed spam filter due to new evasion technique',
            },
            {
              number: 2,
              question: 'Why did our security controls fail to prevent it?',
              focus: 'Prevention control effectiveness',
              example: 'Email security gateway lacked ML-based detection for this attack pattern',
            },
            {
              number: 3,
              question: 'Why was the incident not detected earlier in the attack lifecycle?',
              focus: 'Detection capability gaps',
              example: 'No EDR alerting on suspicious PowerShell execution from Outlook process',
            },
            {
              number: 4,
              question: 'Why did our processes and procedures allow this condition to exist?',
              focus: 'Process and procedural gaps',
              example: 'No regular review cadence for email security rule effectiveness',
            },
            {
              number: 5,
              question: "Why didn't we have adequate mitigations or compensating controls?",
              focus: 'Strategic security posture',
              example: 'Limited security budget prevented purchase of advanced email security platform',
            },
          ].map((item) => (
            <div key={item.number} className="rounded-lg border border-gray-800 bg-gray-950 p-4">
              <div className="flex items-center gap-2 mb-3">
                <span className="flex items-center justify-center w-8 h-8 rounded-full bg-purple-500/10 text-purple-400 text-sm font-bold">
                  {item.number}
                </span>
                <HelpCircle size={20} className="text-purple-500" />
              </div>
              <p className="font-semibold text-gray-100 text-sm mb-2">{item.question}</p>
              <p className="text-xs text-gray-400 mb-2">
                <strong>Focus:</strong> {item.focus}
              </p>
              <div className="rounded bg-gray-800/50 p-2">
                <p className="text-xs text-gray-500 mb-1">Example Answer:</p>
                <p className="text-xs text-gray-300 italic">{item.example}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Templates Grid */}
      <div>
        <h2 className="text-2xl font-bold text-gray-100 mb-4">Post-Mortem Templates</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {TEMPLATES.map((template) => (
            <button
              key={template.id}
              onClick={() => setSelectedTemplate(template)}
              className="text-left rounded-lg border border-gray-800 bg-gray-900 p-6 hover:border-cyan-500/50 hover:bg-gray-800/50 transition-all group"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="rounded-lg bg-cyan-500/10 p-2 group-hover:bg-cyan-500/20 transition-colors">
                    <FileText className="h-5 w-5 text-cyan-500" />
                  </div>
                  <h3 className="font-semibold text-gray-100 group-hover:text-cyan-400 transition-colors">
                    {template.name}
                  </h3>
                </div>
              </div>
              <p className="text-sm text-gray-400 mb-2">{template.description}</p>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <Book size={14} />
                <span>Use case: {template.useCase}</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Template Modal */}
      {selectedTemplate && (
        <>
          <div
            className="fixed inset-0 bg-gray-950/80 backdrop-blur-sm z-50"
            onClick={() => setSelectedTemplate(null)}
            aria-hidden="true"
          />
          <div className="fixed inset-4 z-50 flex items-center justify-center">
            <div className="bg-gray-900 rounded-lg border border-gray-800 shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col">
              {/* Modal Header */}
              <div className="flex items-center justify-between border-b border-gray-800 p-6">
                <div>
                  <h2 className="text-xl font-bold text-gray-100">{selectedTemplate.name}</h2>
                  <p className="text-sm text-gray-400 mt-1">{selectedTemplate.description}</p>
                </div>
                <button
                  onClick={() => setSelectedTemplate(null)}
                  className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-y-auto p-6">
                <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono bg-gray-950 rounded-lg p-4 border border-gray-800">
                  {selectedTemplate.content}
                </pre>
              </div>

              {/* Modal Actions */}
              <div className="border-t border-gray-800 p-4 flex items-center justify-between">
                <p className="text-xs text-gray-500">
                  Markdown format - ready to use in your documentation
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy(selectedTemplate.content)}
                    className="flex items-center gap-2 rounded-md bg-gray-800 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-700 transition-colors"
                  >
                    {copied ? (
                      <>
                        <CheckCircle size={16} className="text-green-500" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy size={16} />
                        Copy
                      </>
                    )}
                  </button>
                  <button
                    onClick={() => handleDownload(selectedTemplate)}
                    className="flex items-center gap-2 rounded-md bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2 text-sm font-medium text-white hover:from-cyan-600 hover:to-blue-700 transition-all"
                  >
                    <Download size={16} />
                    Download
                  </button>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
