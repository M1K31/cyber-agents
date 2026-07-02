---
name: block
description: Block or unblock an IP address on the router via SSH
userInvocable: true
---

# /block Command

Block or unblock an IP address on the ASUS router via SSH iptables rules.

## Usage
```
/block <IP> [--router ROUTER_NAME] [--unblock]
```

## Workflow

1. **Validate IP**: Ensure it's external (not private range)
2. **Load router config** from `~/.aegissiem-daemon/config.yml`
3. **Execute SSH command** using patterns from `skills/router-management.md`
4. **Update database** (insert blocked_ip or set unblocked_at)
5. **Notify** via configured channels (Slack, iMessage)
6. **Confirm** action to operator with details
