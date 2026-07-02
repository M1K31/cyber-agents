---
name: status
description: Show current threat summary, blocked IPs, honeypot activity, and system status
userInvocable: true
---

# /status Command

Display current security posture: threats, blocked IPs, honeypot events, attacker profiles.

## Usage
```
/status [--threats|--blocked|--honeypot|--profiles|--all]
```

## Workflow

1. **Read threat data** from `vault/threat-data/` JSON files and/or query daemon API at `http://localhost:8088/api/status`
2. **Format output**:
   - Active threats with severity and escalation level
   - Currently blocked IPs with block time and method
   - Recent honeypot events
   - Top attacker profiles
   - System health (daemon running, Ollama status, honeypot listeners)
3. **Display** as formatted markdown table
