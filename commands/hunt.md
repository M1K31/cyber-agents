# /hunt — Threat Hunting Command

> Slash command for ingesting log snippets, PCAP summaries, or telemetry data to identify adversary activity, extract IOCs, and generate detection rules.

---

## Usage

```
/hunt <INPUT_TYPE> [OPTIONS]
```

### Arguments

| Argument | Required | Description | Example |
|----------|----------|-------------|---------|
| `INPUT_TYPE` | ✅ | Type of input data | `logs`, `pcap`, `sysmon`, `dns`, `auth` |
| `--data` | ✅ | Inline data or path to file | `--data /path/to/log.json` or paste inline |
| `--hypothesis` | ❌ | Specific threat hypothesis | `--hypothesis "lateral movement via SMB"` |
| `--timeframe` | ❌ | Time window to focus on | `--timeframe "2026-03-17 14:00-16:00"` |
| `--baseline` | ❌ | Path to known-good baseline | `--baseline /path/to/baseline.json` |
| `--output-rules` | ❌ | Generate detection rules | `sigma`, `yara`, `snort`, `all` |

---

## Supported Input Types

| Type | Sources | Key Fields Analyzed |
|------|---------|-------------------|
| `logs` | Generic JSON/text logs | Timestamp, source, event type, message |
| `pcap` | tshark JSON export, Zeek logs | Src/dst IP, ports, protocols, payloads |
| `sysmon` | Windows Sysmon (XML/JSON) | Event IDs 1,3,7,8,10,11,12,13,22 |
| `dns` | DNS query logs, passive DNS | Query name, type, response, frequency |
| `auth` | Authentication logs (AD, SSH, etc.) | User, source IP, success/fail, timestamp |
| `firewall` | FW/IDS logs (CSV, JSON, syslog) | Action, src/dst, port, rule matched |
| `endpoint` | osquery, Velociraptor, EDR telemetry | Process, network, file, registry events |

---

## Execution Workflow

```
STEP 1: INGEST & NORMALIZE
  - Detect input format (JSON, CSV, XML, syslog, plaintext)
  - Parse and normalize to common schema:
    {
      "timestamp": "ISO8601 UTC",
      "source_ip": "",
      "dest_ip": "",
      "source_port": 0,
      "dest_port": 0,
      "protocol": "",
      "event_type": "",
      "user": "",
      "process": "",
      "command_line": "",
      "raw": ""
    }
  - Normalize all timestamps to UTC
  - Count total events, unique sources, unique destinations

STEP 2: THREAT ANALYSIS
  Apply the following detection patterns based on input type:

  A. LATERAL MOVEMENT Detection (T1021)
     - Multiple authentication attempts from single source to many targets
     - SMB/WMI/WinRM connections to non-standard targets
     - PsExec-style service installations (Event ID 7045)
     - Pass-the-Hash indicators (NTLM Type 3 without Type 1/2)
     - RDP connections from unexpected sources

  B. BEACONING Detection (T1071)
     - Regular-interval outbound connections (calculate jitter)
     - Formula: std_dev(intervals) / mean(intervals) < 0.2 = likely beacon
     - Connections to IPs/domains with low reputation
     - Consistent data sizes in requests/responses
     - Unusual hours of operation (outside business hours)
     - DNS beaconing: high-frequency queries to single domain

  C. C2 COMMUNICATION Detection (T1071, T1573)
     - Long-duration connections with periodic data transfer
     - DNS tunneling: unusually long subdomain labels, TXT record abuse
     - HTTP(S) to newly registered domains (< 30 days)
     - JA3/JA3S hash matching against known C2 frameworks
     - Unusual User-Agent strings or missing standard headers

  D. DATA EXFILTRATION Detection (T1048)
     - Large outbound transfers (> baseline)
     - Transfers to cloud storage / file-sharing domains
     - Encoded/encrypted data in DNS queries
     - Unusual protocols for data transfer (ICMP, DNS)
     - After-hours bulk data movement

  E. PRIVILEGE ESCALATION Detection (T1068, T1078)
     - New admin group membership additions
     - Service account login from workstations
     - Unusual process elevation patterns
     - Token manipulation indicators

  F. PERSISTENCE Detection (T1053, T1543, T1547)
     - New scheduled tasks / cron jobs
     - New services or daemons registered
     - Registry run key modifications
     - Startup folder changes
     - New launch agents/daemons (macOS)

STEP 3: CORRELATE & ENRICH
  - Timeline suspicious events chronologically
  - Link related events by entity (user → host → IP → domain)
  - Map identified TTPs to MITRE ATT&CK techniques
  - Classify findings:
    🔴 CONFIRMED — Strong evidence of adversary activity
    🟡 SUSPICIOUS — Anomalous but could be legitimate
    🟢 BENIGN — Explainable activity (document for baseline)
  - For network IOCs, suggest enrichment queries:
    - VirusTotal: `https://www.virustotal.com/gui/ip-address/<IP>`
    - Shodan: `https://www.shodan.io/host/<IP>`
    - GreyNoise: `https://viz.greynoise.io/ip/<IP>`

STEP 4: GENERATE DETECTION RULES (if --output-rules specified)
  For each confirmed or high-confidence finding, generate:

  Sigma Rule:
    - Follow SigmaHQ schema v2
    - Include: title, status, description, references, author, date
    - Include: logsource (category, product, service)
    - Include: detection (selection, filter, condition)
    - Include: falsepositives, level, tags (ATT&CK)

  YARA Rule (if file artifacts found):
    - Follow skills/yara-rule-creation.md patterns
    - Include metadata, optimized conditions

  Snort/Suricata Rule (if network patterns found):
    - Include: action, protocol, src/dst, options (msg, content, sid, rev)

STEP 5: PRODUCE REPORT
  Generate structured hunt report (see Output Format)
```

---

## Detection Pattern: Beaconing Analysis

```python
# Pseudocode for beaconing detection from connection logs
def detect_beaconing(connections, threshold=0.2):
    """
    Group connections by (src_ip, dst_ip, dst_port).
    Calculate interval regularity.
    Jitter ratio < threshold suggests beaconing.
    """
    for group_key, events in group_by(connections, ['src_ip', 'dst_ip', 'dst_port']):
        if len(events) < 10:
            continue  # Need sufficient samples

        intervals = [events[i+1].timestamp - events[i].timestamp
                     for i in range(len(events) - 1)]

        mean_interval = mean(intervals)
        std_interval  = std_dev(intervals)
        jitter_ratio  = std_interval / mean_interval if mean_interval > 0 else 999

        if jitter_ratio < threshold:
            yield {
                'src_ip': group_key.src_ip,
                'dst_ip': group_key.dst_ip,
                'dst_port': group_key.dst_port,
                'beacon_interval': mean_interval,
                'jitter_ratio': jitter_ratio,
                'sample_count': len(events),
                'confidence': 'HIGH' if jitter_ratio < 0.1 else 'MEDIUM'
            }
```

---

## Example Sigma Rule Output

```yaml
title: Potential Lateral Movement via PsExec
id: 8bdf9d7a-9c1a-4b2e-8f3d-1a2b3c4d5e6f
status: experimental
description: Detects potential PsExec-based lateral movement via new service installation
references:
    - https://attack.mitre.org/techniques/T1021/002/
author: cyber-agents
date: 2026/03/17
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 7045
        ServiceName|contains: 'PSEXE'
    filter:
        ServiceName: 'PSExecSvc'
        User|contains: 'SYSTEM'
    condition: selection and not filter
falsepositives:
    - Legitimate PsExec usage by administrators
    - Remote management tools
level: high
```

---

## Output Format

```markdown
## Hunt Report: [Description]

| Field | Value |
|-------|-------|
| **Input Type** | logs / pcap / sysmon |
| **Events Analyzed** | 15,342 |
| **Time Window** | 2026-03-17T14:00:00Z — 2026-03-17T16:00:00Z |
| **Hypothesis** | Lateral movement via SMB |
| **Result** | 🔴 CONFIRMED / 🟡 SUSPICIOUS / 🟢 BENIGN |

### Findings

| # | Finding | ATT&CK | Confidence | Evidence |
|---|---------|--------|------------|----------|
| 1 | Beaconing to 203.0.113.42 every 60s ±3s | T1071.001 | 🔴 HIGH | conn.log lines 1024-1089 |
| 2 | PsExec service installed on 5 hosts | T1021.002 | 🔴 HIGH | Event ID 7045 |
| 3 | Unusual DNS TXT queries to x.evil.com | T1071.004 | 🟡 MEDIUM | dns.log lines 445-460 |

### IOCs Extracted

| Type | Value | Context | Enrichment |
|------|-------|---------|------------|
| IP | 203.0.113.42 | C2 beaconing destination | [VT](link) [Shodan](link) |
| Domain | x.evil.com | DNS tunneling endpoint | [VT](link) |
| SHA256 | abc123... | Dropped binary on SRV-DB03 | [VT](link) |

### Detection Rules Generated

<Sigma / YARA / Snort rules>

### Recommendations

1. **Immediate**: Block 203.0.113.42 at perimeter firewall
2. **Short-term**: Deploy Sigma rule for PsExec detection across SIEM
3. **Long-term**: Implement DNS query length monitoring for tunneling detection
4. **Escalation**: Refer to `incident-responder` agent for containment of SRV-DB03
```
