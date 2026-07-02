# Skill: macOS / Linux Tooling

> Best practices for running security assessment tools on macOS and general Linux environments, focusing on Homebrew-installable and open-source alternatives, with LLM output processing patterns.

---

## Overview

Not every engagement runs from Kali Linux. This skill covers installing, configuring, and operating penetration testing and security monitoring tools on **macOS** (via Homebrew) and standard **Linux** distributions (Debian/Ubuntu, Fedora/RHEL). It also addresses macOS-specific security tooling for endpoint visibility and forensics.

---

## Environment Setup

### macOS — Homebrew Security Toolkit

```bash
# Install Homebrew (if not present)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Core networking & scanning
brew install nmap masscan rustscan netcat socat

# Web application testing
brew install gobuster ffuf nikto httpx nuclei
brew install --cask burp-suite  # Community Edition

# Password & crypto
brew install john-jumbo hashcat hydra

# DNS & OSINT
brew install amass subfinder theHarvester dnsrecon whois

# Packet capture & analysis
brew install wireshark tcpdump tshark termshark

# Binary analysis
brew install radare2 binwalk

# Forensics & monitoring
brew install osquery volatility3 yara

# Python security tools (pip)
pip3 install impacket pwntools scapy droopescan

# Metasploit (via installer or Homebrew)
brew install metasploit
```

### Linux (Debian/Ubuntu) — apt Security Toolkit

```bash
# Core scanning
sudo apt install -y nmap masscan netcat-openbsd socat

# Web testing
sudo apt install -y gobuster nikto sqlmap dirb
# ffuf, httpx, nuclei — install via Go or download binaries
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Password attacks
sudo apt install -y john hashcat hydra

# Packet analysis
sudo apt install -y wireshark tshark tcpdump

# Forensics
sudo apt install -y autopsy sleuthkit volatility3 yara

# Python tools
pip3 install impacket pwntools scapy
```

---

## Cross-Platform Tool Workflows

### 1. Nmap on macOS

Nmap works identically on macOS with one caveat: **raw socket operations require root**.

```bash
# Requires sudo for SYN scans, OS detection
sudo nmap -sS -sV -sC -O -oA scan_results 10.0.0.0/24

# Non-root alternatives (TCP connect scan)
nmap -sT -sV -oA scan_results 10.0.0.0/24

# Service-specific scripts
sudo nmap --script http-enum,http-vuln* -p 80,443 10.0.0.5
sudo nmap --script smb-vuln* -p 445 10.0.0.5
```

### 2. Metasploit on macOS

```bash
# Initialize database (PostgreSQL required)
brew install postgresql@14
brew services start postgresql@14
msfdb init

# Launch Metasploit
msfconsole -q

# Import Nmap results into MSF database
msf> db_import scan_results.xml
msf> services                    # List discovered services
msf> vulns                       # List identified vulnerabilities
```

### 3. Nuclei — Template-Based Vulnerability Scanner

Nuclei is an excellent open-source alternative to commercial scanners, works well on macOS/Linux.

```bash
# Update templates
nuclei -update-templates

# Scan a target with all templates
nuclei -u https://target.example.com -o nuclei_results.json -j

# Scan with specific severity
nuclei -u https://target.example.com -severity critical,high -o critical_findings.json -j

# Scan with specific tags
nuclei -u https://target.example.com -tags cve,owasp -o cve_findings.json -j

# Bulk scan from file
nuclei -l urls.txt -severity critical,high -o bulk_results.json -j -c 50
```

#### LLM Processing Pattern for Nuclei

```
1. Run Nuclei with `-j` (JSON) output
2. Feed JSON to LLM for:
   a. Deduplicate and group findings by template category
   b. Cross-reference CVE IDs with NVD for CVSS scores
   c. Prioritize by severity and exploitability
   d. Identify false positives based on response content
   e. Generate remediation matrix
```

### 4. Impacket — Windows Protocol Toolkit (Python)

Essential for Active Directory and Windows protocol attacks from macOS/Linux.

```bash
# SMB enumeration
impacket-smbclient 'DOMAIN/user:password@target'

# Remote execution
impacket-psexec 'DOMAIN/user:password@target'
impacket-wmiexec 'DOMAIN/user:password@target'
impacket-atexec 'DOMAIN/user:password@target' 'command'

# Credential dumping (requires admin)
impacket-secretsdump 'DOMAIN/user:password@target'

# Kerberos attacks
impacket-GetNPUsers -dc-ip DC_IP DOMAIN/ -usersfile users.txt -format hashcat
impacket-GetUserSPNs -dc-ip DC_IP DOMAIN/user:password -request

# Pass-the-hash
impacket-psexec -hashes :NTLM_HASH 'DOMAIN/user@target'
```

### 5. OSINT Tools

```bash
# theHarvester — email/subdomain enumeration
theHarvester -d target.com -b all -f results.json

# Amass — subdomain enumeration (comprehensive)
amass enum -d target.com -o amass_results.txt -json amass_results.json

# subfinder — fast passive subdomain discovery
subfinder -d target.com -o subdomains.txt -oJ -all

# httpx — probe discovered subdomains
cat subdomains.txt | httpx -status-code -title -tech-detect -json -o live_hosts.json
```

---

## macOS-Specific Security Tools

### Endpoint Visibility

| Tool | Purpose | Installation |
|------|---------|-------------|
| **osquery** | SQL-based endpoint querying | `brew install osquery` |
| **Santa** | Binary authorization / allowlist | [GitHub releases](https://github.com/google/santa) |
| **BlockBlock** | Persistence detection | [Objective-See](https://objective-see.org/products/blockblock.html) |
| **KnockKnock** | Startup item enumeration | [Objective-See](https://objective-see.org/products/knockknock.html) |
| **LuLu** | Application-level firewall | [Objective-See](https://objective-see.org/products/lulu.html) |
| **Crescendo** | Real-time event monitoring | `brew install crescendo` |
| **ProcessMonitor** | Process event monitoring | [Objective-See](https://objective-see.org/products/processmonitor.html) |

### osquery — Endpoint Querying

```sql
-- List listening ports
SELECT pid, port, protocol, address FROM listening_ports WHERE address != '127.0.0.1';

-- Running processes with network connections
SELECT p.name, p.pid, p.path, p.cmdline, pp.remote_address, pp.remote_port
FROM processes p
JOIN process_open_sockets pp ON p.pid = pp.pid
WHERE pp.remote_port != 0;

-- Find persistence mechanisms (launch agents/daemons)
SELECT * FROM launchd WHERE run_at_load = 1;

-- Detect unsigned or ad-hoc signed binaries
SELECT path, signing_id, authority FROM signature WHERE authority = '' OR authority IS NULL;

-- Browser extensions (potential spyware)
SELECT * FROM safari_extensions;
SELECT * FROM chrome_extensions;

-- Kext (kernel extensions) loaded
SELECT * FROM kernel_extensions WHERE name NOT LIKE 'com.apple%';

-- Recent file downloads
SELECT * FROM extended_attributes WHERE key = 'com.apple.quarantine';

-- Shell history
SELECT * FROM shell_history ORDER BY time DESC LIMIT 50;
```

### macOS Unified Logging

```bash
# Export full log archive for analysis
sudo log collect --output /tmp/system_logs.logarchive

# Search for specific subsystem
log show --predicate 'subsystem == "com.apple.securityd"' --last 24h

# SSH authentication events
log show --predicate 'process == "sshd"' --last 24h

# Process execution events
log show --predicate 'eventMessage CONTAINS "exec"' --last 1h

# Network connections
log show --predicate 'subsystem == "com.apple.networkd"' --last 24h

# Stream live events (for real-time monitoring)
log stream --predicate 'subsystem == "com.apple.securityd"' --level debug
```

### macOS Forensic Artifacts

| Artifact | Location | Purpose |
|----------|----------|---------|
| Unified logs | `/var/db/diagnostics/`, `.logarchive` | System-wide event logging |
| FSEvents | `/.fseventsd/` | File system change history |
| Spotlight metadata | `/.Spotlight-V100/` | File metadata index |
| Quarantine DB | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | Downloaded file tracking |
| KnowledgeC | `~/Library/Application Support/Knowledge/knowledgeC.db` | Application usage history |
| TCC.db | `~/Library/Application Support/com.apple.TCC/TCC.db` | Permission grants |
| Keychain | `~/Library/Keychains/` | Stored credentials |
| Launch agents | `~/Library/LaunchAgents/`, `/Library/LaunchAgents/` | User/system persistence |
| Login items | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` | Login persistence |

---

## LLM Integration Patterns for macOS/Linux

### Pattern 1: Tool Output → Structured Analysis

```
1. Run tool with structured output flag (JSON, XML, CSV)
2. Pipe output to LLM with context:
   - Tool name and version
   - Target description
   - Engagement scope
3. Request:
   - Severity-ranked findings
   - ATT&CK technique mapping
   - False positive assessment
   - Next-step recommendations
```

### Pattern 2: Log Correlation

```
1. Collect logs from multiple sources:
   - osquery scheduled query results
   - Unified log exports
   - Network captures (tshark JSON)
2. Feed correlated timeline to LLM:
   - Focus on temporal correlations (±5 minute windows)
   - Flag process → network → file chains
   - Identify anomalous patterns vs. baseline
```

### Pattern 3: Continuous Monitoring Analysis

```
1. Set up scheduled data collection:
   - osquery differential results
   - File integrity monitoring deltas
   - New network connections
2. Feed deltas to LLM periodically:
   - Highlight changes from baseline
   - Flag new persistence mechanisms
   - Identify unauthorized software installations
```

---

## Platform Compatibility Matrix

| Tool | macOS | Linux (Debian) | Linux (RHEL) | Notes |
|------|-------|----------------|--------------|-------|
| Nmap | ✅ `brew` | ✅ `apt` | ✅ `dnf` | Requires sudo for SYN scan |
| Metasploit | ✅ `brew` | ✅ installer | ✅ installer | Needs PostgreSQL |
| Burp Suite | ✅ `brew --cask` | ✅ download | ✅ download | Java-based, cross-platform |
| Nuclei | ✅ `brew` | ✅ `go install` | ✅ `go install` | Best OSS alternative to commercial scanners |
| osquery | ✅ `brew` | ✅ `apt` | ✅ `rpm` | Native macOS ESF integration |
| Wireshark | ✅ `brew --cask` | ✅ `apt` | ✅ `dnf` | GUI ; use `tshark` for CLI |
| Impacket | ✅ `pip3` | ✅ `pip3` | ✅ `pip3` | Python-based, fully cross-platform |
| John the Ripper | ✅ `brew` | ✅ `apt` | ✅ `dnf` | Use `john-jumbo` for full features |
| YARA | ✅ `brew` | ✅ `apt` | ✅ `dnf` | Identical behavior cross-platform |
