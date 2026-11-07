# Cyber Agents — Usage & Operational Guide

This guide covers operational lifecycle commands, autonomous daemon execution, dashboard interaction, and cross-application workflows with `appEcosystem`, `AegisSIEM`, and `AI-for-Survival`.

---

## 1. Service Lifecycle Management

The `cyber-agents` runtime includes both interactive Claude Code agent workflows and an autonomous background analysis daemon (`daemon.aegissiem_daemon`).

### Local Installation
```bash
# Build internal-disk venv and dependencies (no background service started)
./scripts/install-local.sh

# Optional: Install and enable persistent background LaunchAgent (macOS)
./scripts/install-local.sh --plist
```

### Running the Autonomous SOC Daemon
```bash
# Direct execution using the isolated runtime:
~/.local/share/cyber-harness/venv/bin/python -m daemon.aegissiem_daemon

# Environment overrides:
AEGISSIEM_PORT=8088 \
OLLAMA_URL="http://127.0.0.1:11434" \
AI_MODEL="security_analysis:heretic-llama3.1-8b-q4" \
~/.local/share/cyber-harness/venv/bin/python -m daemon.aegissiem_daemon
```

### Stopping the Service
```bash
# If installed via LaunchAgent:
launchctl bootout "gui/$(id -u)/com.smartindustries.cyber-harness"

# If running directly:
pkill -f "daemon.aegissiem_daemon"
```

---

## 2. Web Dashboard & Apple HIG Control Plane

The daemon hosts a real-time SOC triage dashboard on port **8088**:

👉 **`http://127.0.0.1:8088/dashboard`**

### Dashboard Features
- **Stat Cards**: Real-time counters for Open Threats, Blocked IPs, Active Profiles, 24h Honeypot Events, and Pending Approvals.
- **Apple HIG Web Components**:
  - `<ecosystem-policy-bar>`: Displays current policy posture (`normal`, `incident`, `emergency`, `survival`, `freeze`).
  - `<ecosystem-override-modal>`: Allows authenticated administrators to request situational exceptions or temporary policy bypasses.
- **Two-Factor Step-Up Authentication**:
  - Click **Setup 2FA** to generate a local RFC 6238 TOTP seed.
  - Enter 6-digit TOTP code in the top header to authorize privileged action classes (`contain`, `remediate`, `system_change`).

---

## 3. Slash Commands & Interactive Agent Workflows

In Claude Code, invoke cybersecurity workflows using slash commands or direct delegation:

```bash
# Reconnaissance workflow (nmap profiles: quick, standard, full, stealth)
/scan 192.168.1.0/24

# Threat hunting from raw syslog, auth log, or PCAP snippet
/hunt "Mar 04 03:55:16 router dropbear[1842]: Bad password attempt for 'root' from 45.227.253.13"

# Delegate to specialized role
"Use threat-hunter to correlate recent SSH brute-force attempts with Sigma rule matches."
```

---

## 4. Cross-Application Integration Examples

### Example 1: Autonomous Triage of AegisSIEM Syslog Events
`cyber-agents` tails router syslogs ingested by `AegisSIEM` or listens for canonical `security.threat` events over the ecosystem mesh:

```python
from daemon.ecosystem_bridge import get_policy_engine, get_approval_queue
from ecosystem_policy import ActionRequest

# 1. Ingest threat detected by AegisSIEM
threat = {
    "source_ip": "45.227.253.13",
    "threat_type": "brute_force",
    "severity": "HIGH",
    "attempts": 25392
}

# 2. Check proposed containment against ecosystem policy
engine = get_policy_engine()
action = ActionRequest(
    actor="cyber-agents/triage-daemon",
    model="security_analysis:local-llama3",
    action="block_ip",
    action_class="contain",
    target={"ip": threat["source_ip"]},
    rationale="Repeated brute force exceeding 25,000 attempts."
)

decision = engine.decide(action)
if decision.result in ("allow", "allow_and_notify"):
    # Apply temporary block and schedule automated rollback
    print(f"Action allowed: {decision.notice}")
elif decision.result == "require_approval":
    # Submit to approvals queue; surfaces in AegisSIEM and Control Plane UIs
    queue = get_approval_queue()
    await queue.enqueue(action, deadline=decision.deadline)
```

---

### Example 2: Correlating with AI-for-Survival Offline RAG
When investigating zero-day behaviors or unmapped techniques, `cyber-agents` queries `AI-for-Survival` for offline defense playbooks:

```python
import httpx

async def lookup_mitre_guidance(technique_id: str):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://127.0.0.1:8000/api/knowledge/search",
            json={"query": f"MITRE ATT&CK {technique_id} containment and forensic steps", "top_k": 1}
        )
        if resp.status_code == 200:
            return resp.json()["results"][0]["content"]
    return "No offline playbook found."
```

---

### Example 3: Initiating Endpoint Forensic Verification with ZBT
If an internal endpoint is suspected of compromise, `cyber-agents` requests an authorized scan via the central `ScanRunner`:

```python
import httpx
from ecosystem_auth.tokens import sign_request, get_ecosystem_secret

secret = get_ecosystem_secret()
url = "http://127.0.0.1:8500/scans/run"
payload = {
    "device_id": "example-workstation",
    "profile": "standard",
    "reason": "Correlated lateral movement alert"
}

headers = sign_request("POST", url, secret, payload)
async with httpx.AsyncClient() as client:
    res = await client.post(url, json=payload, headers=headers)
    scan_job = res.json()
    print(f"Enqueued forensic audit: {scan_job['scan_id']}")
```

