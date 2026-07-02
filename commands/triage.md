---
name: triage
description: Run a multi-step incident triage workflow for a threat IP
userInvocable: true
---

# /triage Command

Execute a multi-step triage workflow combining log analysis, recon, and LLM assessment.

## Usage
```
/triage <IP> [--playbook incident_triage|log_analysis|security_scan]
```

## Playbooks

### incident_triage (default)
1. **Collect**: Gather all threat events for the IP from database
2. **Profile**: Run WHOIS, rDNS, GeoIP enrichment
3. **Analyze**: Query Ollama qwen2.5-coder for threat assessment
4. **Correlate**: Check for related IPs in same /24 subnet
5. **Recommend**: Suggest response actions (block, monitor, investigate)
6. **Report**: Generate structured incident report

### log_analysis
1. **Collect**: Pull recent syslog data
2. **Parse**: Classify all events using syslog patterns
3. **Detect**: Apply detection rules
4. **Summarize**: Generate analysis report via Ollama

### security_scan
1. **Ecosystem health**: Check all registered services
2. **Threat summary**: Aggregate open threats
3. **Honeypot review**: Analyze captured credentials and commands
4. **Recommendations**: Generate security posture report

## Output
Structured markdown report saved to `vault/threat-data/triage-{IP}-{timestamp}.md`
