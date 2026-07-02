# /scan — Network Reconnaissance Command

> Slash command for executing network scans, parsing results, and producing actionable intelligence.

---

## Usage

```
/scan <TARGET> [OPTIONS]
```

### Arguments

| Argument | Required | Description | Example |
|----------|----------|-------------|---------|
| `TARGET` | ✅ | IP address, CIDR range, hostname, or domain | `10.0.0.0/24`, `target.example.com` |
| `--profile` | ❌ | Scan profile (see below) | `--profile stealth` |
| `--ports` | ❌ | Port specification | `--ports 80,443,8080` or `--ports top100` |
| `--output` | ❌ | Output directory | `--output ./scan_results` |
| `--os-detect` | ❌ | Enable OS fingerprinting | Flag, no value |
| `--vuln-scan` | ❌ | Run NSE vulnerability scripts | Flag, no value |

---

## Scan Profiles

| Profile | Nmap Flags | Use Case | Noise Level |
|---------|-----------|----------|-------------|
| `discovery` | `-sn -PE -PP -PM` | Host discovery only (no port scan) | 🟢 Low |
| `quick` | `-sS -sV --top-ports 100 -T3` | Fast top-100 port scan with service detection | 🟡 Medium |
| `standard` | `-sS -sV -sC -O --open -T3` | Full TCP SYN scan, scripts, OS detection | 🟡 Medium |
| `full` | `-sS -sV -sC -O -p- --open -T3` | All 65535 TCP ports | 🔴 High |
| `stealth` | `-sS -T2 -f --data-length 24 -D RND:3` | Evasive scan with decoys and fragmentation | 🟢 Low |
| `udp` | `-sU -sV --top-ports 50` | Top 50 UDP ports | 🟡 Medium |
| `vuln` | `--script vuln -sV` | NSE vulnerability scripts | 🔴 High |

---

## Execution Workflow

```
STEP 1: VALIDATE Input
  - Parse TARGET: Validate IP/CIDR notation or resolve hostname
  - Confirm TARGET is within authorized engagement scope
  - Check if Nmap is installed: `which nmap`
  - If not found, suggest: `brew install nmap` (macOS) or `sudo apt install nmap` (Linux)

STEP 2: SELECT Scan Profile
  - If --profile specified, use corresponding Nmap flags
  - If not specified, recommend based on context:
    - First scan of a new target → `discovery` then `quick`
    - Follow-up on specific hosts → `standard`
    - Comprehensive assessment → `full`
    - Evasion required → `stealth`
  - Always add `-oA <output_prefix>` for all three output formats

STEP 3: EXECUTE Scan
  - Construct full Nmap command
  - Display command to operator for confirmation before execution
  - Run with appropriate privileges (sudo for SYN scans)
  - Monitor progress and display estimated completion time

STEP 4: PARSE Results
  Parse the .nmap (normal) output and produce structured summary:

  a. Host Summary Table:
     | IP | Hostname | State | OS Guess | Open Ports |
     |----|----------|-------|----------|------------|

  b. Port Detail Table (per host):
     | Port | Protocol | State | Service | Version | Notes |
     |------|----------|-------|---------|---------|-------|

  c. Actionable Findings:
     - Services with known CVEs (match version against NVD)
     - Default/insecure configurations detected by NSE scripts
     - Unusual ports or services that warrant investigation

  d. Next Steps:
     - Recommend specific tools for discovered services:
       Port 80/443 → Nikto, Gobuster, Nuclei
       Port 445 → enum4linux-ng, CrackMapExec
       Port 22 → SSH banner analysis, auth testing
       Port 3389 → RDP security check
       Port 3306/5432 → DB auth testing

STEP 5: STORE Results
  - Save all output files to --output directory (or ./scans/<timestamp>/)
  - Generate markdown summary at <output>/scan_summary.md
  - If Metasploit DB is active, import XML: `db_import scan.xml`
  - Log scan execution in vault/progress-log.md
```

---

## Example Session

```
Operator: /scan 192.168.1.0/24 --profile quick

Agent: I'll run a quick scan of the 192.168.1.0/24 range.

Proposed command:
  sudo nmap -sS -sV --top-ports 100 -T3 -oA ./scans/20260317_quick 192.168.1.0/24

Shall I proceed? [Confirm target is in scope]

--- After scan ---

## Scan Summary: 192.168.1.0/24

**Hosts discovered**: 12 / 254
**Scan duration**: 47 seconds

### Host Overview

| IP | Hostname | Open Ports | Notable Services |
|----|----------|------------|-----------------|
| 192.168.1.1 | gateway.local | 80, 443, 8443 | HTTP (nginx 1.18), HTTPS |
| 192.168.1.10 | dc01.corp.local | 53, 88, 135, 389, 445, 636 | DNS, Kerberos, LDAP, SMB |
| 192.168.1.50 | web01.corp.local | 22, 80, 443 | SSH (OpenSSH 8.2), Apache 2.4.41 |
| ... | ... | ... | ... |

### ⚠️ Actionable Findings

1. **Apache 2.4.41** on 192.168.1.50 — CVE-2021-41773 (Path Traversal, CVSS 7.5)
2. **SMB signing disabled** on 192.168.1.10 — enables relay attacks (T1557.001)
3. **SSH password auth enabled** on 192.168.1.50 — brute-force risk

### Recommended Next Steps

- `192.168.1.50:80` → Run `/scan 192.168.1.50 --profile vuln` for deep vulnerability check
- `192.168.1.10:445` → Run `enum4linux-ng 192.168.1.10` for AD enumeration
- `192.168.1.1:8443` → Check for admin panel, default credentials
```

---

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `Nmap not found` | Not installed | `brew install nmap` or `apt install nmap` |
| `Permission denied` | SYN scan requires root | Run with `sudo` or use `-sT` (TCP connect) |
| `Host seems down` | ICMP blocked | Add `-Pn` to skip host discovery |
| `Scan taking too long` | Large range + full port scan | Reduce scope or use `--top-ports` |
| `Rate limiting detected` | IDS/firewall throttling | Switch to `stealth` profile, reduce `-T` value |
