---
name: Syslog Analysis
description: ASUS router syslog parsing patterns, detection rules, and escalation thresholds
---

# Syslog Analysis Skill

## Log Format
ASUS router syslog follows: `Mon DD HH:MM:SS source: message`

## Event Patterns

### Login Events
Pattern: `HTTPD: [LOGIN][https][Web|APP] fail|success|captcha error (IP_ADDRESS)`
- `fail` → EventType.LOGIN_FAIL
- `success` → EventType.LOGIN_SUCCESS
- `captcha error` → EventType.CAPTCHA_ERROR

### Deauth Events
Pattern: `Deauth_ind MAC_ADDRESS, status: N, reason: REASON_TEXT (CODE)`
- Filter band steering: "Previous authentication no longer valid", "Deauthenticated because sending station is leaving..."

### DNS Rebinding
Pattern: `DNS rebind` (case-insensitive anywhere in message)

## Detection Thresholds

### Brute Force (Burst)
- **Trigger**: 5+ login failures from same IP within 3600 seconds (1 hour)
- **Severity**: HIGH
- **Auto-block delay**: 10800 seconds (3 hours)

### Brute Force (Slow)
- **Trigger**: 10+ cumulative login failures from same IP (any timeframe)
- **Severity**: HIGH

### Brute Force Success
- **Trigger**: Login success from IP with previous failures
- **Severity**: CRITICAL (compromise indicator)

### Deauth Flood
- **Trigger**: 20+ deauth events in 60 seconds (excluding band steering)
- **Severity**: MEDIUM

### DNS Rebinding
- **Trigger**: Any DNS rebind not in whitelist (chromecast, google, localhost)
- **Severity**: MEDIUM

## Escalation State Machine

```
OBSERVE (0) → ALERT (1) → CONTAIN (2) → PROFILED (25) → INVESTIGATE (3)
```

| Level | Name | Trigger | Response |
|-------|------|---------|----------|
| 0 | OBSERVE | Initial detection | Monitor, log |
| 1 | ALERT | 10+ cumulative attempts | Normal honeypot, notify |
| 2 | CONTAIN | 50+ attempts or aggressive behavior | Tarpit honeypot, auto-block |
| 25 | PROFILED | Full recon complete | PROCEED/STOP checkpoint |
| 3 | INVESTIGATE | Operator approves PROCEED | Active investigation |

Rules:
- Never de-escalate
- PROFILED (25) is a checkpoint — requires manual approval
- Escalation propagates to /24 subnet peers
