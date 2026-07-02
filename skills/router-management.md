---
name: Router Management
description: SSH-based ASUS router administration - iptables blocking, syslog retrieval, status checks
---

# Router Management Skill

## Prerequisites
- SSH key at `~/.ssh/router_rsa`
- Router SSH enabled (Administration > System > Enable SSH)
- Router IP in config at `~/.aegissiem-daemon/config.yml`

## Block IP
```bash
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP \
  "iptables -I INPUT -s ATTACKER_IP -j DROP && iptables -I FORWARD -s ATTACKER_IP -j DROP"
```

## Unblock IP
```bash
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP \
  "iptables -D INPUT -s ATTACKER_IP -j DROP 2>/dev/null; \
   iptables -D FORWARD -s ATTACKER_IP -j DROP 2>/dev/null; \
   echo done"
```

## List Blocked IPs
```bash
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP \
  "iptables -L INPUT -n --line-numbers | grep DROP"
```

## Retrieve Syslog
```bash
# From router's syslog buffer
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP "cat /tmp/syslog.log"

# Last N lines
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP "tail -n 200 /tmp/syslog.log"
```

## Router Status
```bash
# Connected clients
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP "cat /proc/net/arp"

# Current connections
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP "cat /proc/net/nf_conntrack | wc -l"

# Uptime
ssh -i ~/.ssh/router_rsa admin@ROUTER_IP "uptime"
```

## Safety Notes
- Always validate IPs before blocking (never block gateway, DNS, or internal ranges)
- iptables rules are lost on router reboot — daemon reapplies from database
- SSH timeout: 10 seconds connect, 10 seconds command
- Retry once on SSH failure before reporting error
