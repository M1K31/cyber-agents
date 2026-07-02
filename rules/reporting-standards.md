# Rule: Reporting Standards

> **Enforcement Level**: MANDATORY — All vulnerability reports, incident summaries, and hunt findings MUST follow these templates. Non-compliant reports will be rejected.

---

## Purpose

This rule defines the mandatory structure, content, and formatting standards for all security reports produced by agents. Consistent, high-quality reporting ensures findings are actionable, defensible, and aligned with industry frameworks (CVSS v3.1, MITRE ATT&CK, NIST, OWASP).

---

## 1. Report Types

| Report Type | Agent(s) | When Produced |
|-------------|----------|---------------|
| **Vulnerability Report** | exploit-researcher, red-team-lead | Per finding or grouped by target |
| **Engagement Summary** | red-team-lead | End of engagement |
| **Incident Summary** | incident-responder | Per incident (PICERL completion) |
| **Hunt Report** | threat-hunter | Per hunt hypothesis |
| **Detection Rule Package** | threat-hunter | When new rules are authored |

---

## 2. Vulnerability Report Template

Every vulnerability finding MUST use this template. No fields may be omitted — use "N/A" if genuinely not applicable.

````markdown
## [FINDING-NNN] [Vulnerability Title]

### Summary

| Field | Value |
|-------|-------|
| **Finding ID** | FINDING-NNN |
| **Severity** | Critical / High / Medium / Low / Informational |
| **CVSS v3.1 Score** | X.X |
| **CVSS v3.1 Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE ID** | CVE-YYYY-NNNNN (or "N/A — zero-day / custom finding") |
| **CWE ID** | CWE-XXX — Weakness Name |
| **MITRE ATT&CK** | TXXXX.XXX — Technique Name |
| **OWASP Category** | A01:2021 — Broken Access Control (if web) |
| **Affected Asset** | hostname / IP:port / URL |
| **Affected Software** | Product vX.X.X |
| **Discovery Date** | YYYY-MM-DD |
| **Status** | Open / Remediated / Accepted Risk / False Positive |

### Description

Provide a clear, technical description of the vulnerability. Include:
- What the vulnerability is
- Where it exists (specific endpoint, function, configuration)
- Why it is exploitable

### Proof of Concept

```
[Include exact steps to reproduce]
[Include tool commands, request/response pairs, or code]
[Redact any sensitive data per rules/data-handling.md]
```

### Evidence

| # | Description | Reference |
|---|-------------|-----------|
| 1 | Nmap output showing vulnerable service version | evidence/nmap_srv01.txt |
| 2 | HTTP request/response demonstrating injection | evidence/sqli_request.txt |
| 3 | Screenshot of admin panel access | evidence/admin_access.png |

### Impact

Describe the business and technical impact:
- **Confidentiality**: What data could be exposed?
- **Integrity**: What data or systems could be modified?
- **Availability**: Could this cause an outage?
- **Business Impact**: What is the real-world consequence?

### Remediation

| Priority | Action | Effort |
|----------|--------|--------|
| **Primary** | [Specific patch, upgrade, or configuration change] | [Hours/Days] |
| **Workaround** | [Temporary mitigation if patch unavailable] | [Hours/Days] |
| **Compensating** | [Additional control: WAF rule, network segmentation] | [Hours/Days] |

### References

- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN)
- [Vendor Advisory](https://example.com/advisory)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/TXXXX/)
- [OWASP Reference](https://owasp.org/Top10/)
````

---

## 3. Engagement Summary Template

````markdown
# Engagement Report — [Engagement Name]

## Executive Summary

| Field | Value |
|-------|-------|
| **Engagement ID** | ENG-YYYY-NNN |
| **Client** | [Organization Name] |
| **Type** | External Pentest / Internal Pentest / Web App / Red Team |
| **Date Range** | YYYY-MM-DD — YYYY-MM-DD |
| **Testers** | [Operator names/handles] |
| **Overall Risk Rating** | Critical / High / Medium / Low |

### Key Findings Summary

| # | Finding | Severity | CVSS | Status |
|---|---------|----------|------|--------|
| 1 | [Title] | Critical | 9.8 | Open |
| 2 | [Title] | High | 7.5 | Open |
| 3 | [Title] | Medium | 5.3 | Open |

### Risk Heatmap

| | Critical | High | Medium | Low | Info |
|--|----------|------|--------|-----|------|
| **Count** | X | X | X | X | X |

### Executive Narrative

[2-3 paragraph non-technical summary of the engagement. Written for
C-suite and board-level audiences. Focus on business risk, not technical
details. Include the "so what?" for each major finding.]

## Methodology

Describe the methodology used, mapped to the engagement phases:

1. **Reconnaissance** — ATT&CK TA0043
2. **Initial Access** — ATT&CK TA0001
3. **Execution** — ATT&CK TA0002
4. **Persistence** — ATT&CK TA0003
5. **Privilege Escalation** — ATT&CK TA0004
6. **Defense Evasion** — ATT&CK TA0005
7. **Credential Access** — ATT&CK TA0006
8. **Discovery** — ATT&CK TA0007
9. **Lateral Movement** — ATT&CK TA0008
10. **Collection** — ATT&CK TA0009
11. **Exfiltration** — ATT&CK TA0010

## Scope

[Copy the scope document from rules/safe-harbor.md]

## Detailed Findings

[Include each finding using the Vulnerability Report Template above]

## ATT&CK Navigator Heatmap

[List all ATT&CK techniques executed during the engagement, grouped by tactic]

| Tactic | Techniques Used |
|--------|----------------|
| Reconnaissance | T1595.002, T1592 |
| Initial Access | T1190 |
| Execution | T1059.001 |
| ... | ... |

## Recommendations Summary

| Priority | Recommendation | Findings Addressed | Est. Effort |
|----------|---------------|-------------------|-------------|
| 1 (Critical) | [Recommendation] | FINDING-001, FINDING-003 | X days |
| 2 (High) | [Recommendation] | FINDING-002 | X days |
| ... | ... | ... | ... |

## Appendices

### A. Tool List

| Tool | Version | Purpose |
|------|---------|---------|
| Nmap | 7.94 | Port scanning and service detection |
| Metasploit | 6.3.x | Exploitation framework |
| ... | ... | ... |

### B. Artifact Manifest

[Reference from rules/opsec.md — list of all deployed artifacts with cleanup status]

### C. Cleanup Verification

| # | Artifact | Target | Deployed | Cleaned | Verified |
|---|----------|--------|----------|---------|----------|
| 1 | stager.dll | SRV-WEB01 | 2026-03-15 | 2026-03-17 | ✅ |
````

---

## 4. Incident Summary Template

````markdown
# Incident Report — INC-YYYY-MMDD-NNN

## Executive Summary

| Field | Value |
|-------|-------|
| **Incident ID** | INC-YYYY-MMDD-NNN |
| **Severity** | P1-Critical / P2-High / P3-Medium / P4-Low |
| **Status** | Detected / Contained / Eradicated / Recovered / Closed |
| **Detection Source** | SIEM alert / EDR / Threat hunt / User report |
| **Detection Time** | YYYY-MM-DDTHH:MM:SSZ |
| **Containment Time** | YYYY-MM-DDTHH:MM:SSZ |
| **Resolution Time** | YYYY-MM-DDTHH:MM:SSZ |
| **MTTD** | [Mean Time to Detect] |
| **MTTC** | [Mean Time to Contain] |
| **MTTR** | [Mean Time to Resolve] |

## Incident Classification

| Field | Value |
|-------|-------|
| **Category** | Malware / Phishing / Unauthorized Access / Data Breach / DoS / Insider |
| **ATT&CK Tactics** | TA0001, TA0002, TA0008 |
| **ATT&CK Techniques** | T1566.001, T1059.001, T1021.002 |
| **Initial Access Vector** | [How the adversary got in] |
| **Affected Systems** | [List of impacted hosts/services] |
| **Data Impact** | [What data was accessed/exfiltrated/modified] |
| **Business Impact** | [Revenue, reputation, regulatory, operational] |

## Timeline

| Time (UTC) | Phase | Actor | Event | Evidence Source |
|------------|-------|-------|-------|-----------------|
| HH:MM:SSZ | Initial Access | Adversary | [Description] | [Source] |
| HH:MM:SSZ | Execution | Adversary | [Description] | [Source] |
| HH:MM:SSZ | Detection | Defender | [Description] | [Source] |
| HH:MM:SSZ | Containment | Defender | [Description] | [Source] |

## Root Cause Analysis

### Initial Access Vector
[Detailed description of how the adversary gained initial access]

### Exploitation Chain
[Step-by-step description with ATT&CK mapping]

### Contributing Factors
[What systemic weaknesses enabled this incident]

## Response Actions Taken

### Containment
[Specific containment actions with timestamps]

### Eradication
[What was removed and verified]

### Recovery
[How systems were restored and validated]

## IOCs

| Type | Value | Context |
|------|-------|---------|
| SHA256 | [hash] | Malware sample |
| IP | [address] | C2 server |
| Domain | [domain] | Staging infrastructure |

## Lessons Learned

### What Worked
- [Positive outcomes]

### What Needs Improvement
- [Gaps identified]

### Recommendations

| # | Recommendation | Priority | Owner | Deadline |
|---|---------------|----------|-------|----------|
| 1 | [Specific action] | Critical | [Team] | [Date] |
| 2 | [Specific action] | High | [Team] | [Date] |
````

---

## 5. CVSS v3.1 Scoring Guide

Agents MUST compute CVSS scores accurately. Reference table:

| Metric | Values | Weight Guidance |
|--------|--------|----------------|
| **Attack Vector (AV)** | Network (0.85) / Adjacent (0.62) / Local (0.55) / Physical (0.20) | How can the attacker reach the target? |
| **Attack Complexity (AC)** | Low (0.77) / High (0.44) | Are special conditions needed? |
| **Privileges Required (PR)** | None (0.85) / Low (0.62/0.68) / High (0.27/0.50) | What access level is needed? |
| **User Interaction (UI)** | None (0.85) / Required (0.62) | Does a user need to do something? |
| **Scope (S)** | Unchanged / Changed | Can it affect other components? |
| **Confidentiality (C)** | None / Low / High | Data exposure impact |
| **Integrity (I)** | None / Low / High | Data modification impact |
| **Availability (A)** | None / Low / High | Service disruption impact |

### Severity Mapping

| Score | Severity | Report Color |
|-------|----------|-------------|
| 9.0 – 10.0 | 🔴 Critical | Red |
| 7.0 – 8.9 | 🟠 High | Orange |
| 4.0 – 6.9 | 🟡 Medium | Yellow |
| 0.1 – 3.9 | 🔵 Low | Blue |
| 0.0 | ⚪ Informational | Gray |

---

## 6. Formatting Standards

```
MANDATORY FORMAT RULES:

1. All reports MUST be in Markdown format
2. Use tables for structured data — never inline lists for findings metadata
3. Timestamps MUST be UTC in ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
4. CVSS vectors MUST use the official v3.1 notation
5. ATT&CK references MUST include both the technique ID and name
6. All evidence MUST be referenced (not embedded) to keep reports portable
7. Sensitive data MUST be redacted per rules/data-handling.md
8. Reports MUST include a table of contents for documents > 3 sections
9. Findings MUST be ordered by severity (Critical → Informational)
10. Each finding MUST have a unique, sequential ID (FINDING-001, FINDING-002)
```
