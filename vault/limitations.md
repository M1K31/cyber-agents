# ⚠️ Limitations

> Known limitations, constraints, and boundaries of the cyber-claude-agents harness.

---

## Architectural Limitations

### LLM Context Window
- **Agent memory is session-scoped** — no persistent state between Claude Code sessions
- Campaign state, findings, and engagement progress must be manually tracked in `vault/` files
- Large tool outputs (full Nmap scans, big log files) may exceed context limits — use `--top-ports`, time-bound queries, and pagination
- Complex multi-phase engagements require the operator to carry state between sessions via the vault

### Inter-Agent Communication
- **No automated agent-to-agent protocol** — delegation is operator-mediated
- The active-engagement context suggests delegation patterns, but the operator must manually route outputs between agents
- No shared memory or state bus between concurrent agent sessions

### Hook Limitations
- **Scope check is regex-based** — it extracts IPs/domains from command strings but cannot parse all possible tool argument formats
- Obfuscated or indirectly-specified targets (environment variables, config file references) will bypass scope validation
- IOC extractor has inherent false positive rates, especially for MD5 hashes (32 hex chars match many non-hash strings)
- Session sanitizer processes text fields only — binary data in session context is not scanned

---

## Tool & Platform Gaps

### Operating System Coverage
| Platform | Support Level | Notes |
|----------|--------------|-------|
| Kali Linux | ✅ Full | Primary offensive platform |
| macOS | ✅ Full | Homebrew tooling + native forensic artifacts |
| Ubuntu/Debian | ✅ Full | apt-based tooling |
| Windows | ⚠️ Partial | Agent prompts reference Windows artifacts (Sysmon, Event Logs, registry) but operator workstation workflows are Linux/macOS focused |
| Cloud (AWS/GCP/Azure) | ❌ Not covered | No dedicated cloud security agent yet |
| Containers (Docker/K8s) | ❌ Not covered | No container-specific scanning workflows |

### Detection Rule Coverage
| Rule Type | Coverage | Gaps |
|-----------|----------|------|
| YARA (PE files) | ✅ Strong | Templates for PE and PHP webshells |
| YARA (ELF/Mach-O) | ⚠️ Limited | No dedicated templates yet |
| Sigma (Sysmon) | ✅ Strong | Well-covered via SPL patterns |
| Sigma (auditd/Linux) | ⚠️ Limited | Few pre-built patterns |
| Sigma (macOS unified log) | ❌ Minimal | Not yet developed |
| Snort/Suricata | ⚠️ Basic | Complex protocol dissection requires manual tuning |

### MCP Server Limitations
- **API rate limits** apply — Shodan free (1 req/s), VirusTotal free (4 req/min, 500/day)
- **VirusTotal submissions are public** — submitted URLs and files become part of VT's dataset; never submit confidential files
- **Splunk config requires network access** — the operator workstation must reach the Splunk REST API (port 8089 default)
- **No offline mode** — MCP servers require internet/network connectivity
- Elasticsearch alternative config is provided but not as deeply templated as the Splunk tools

---

## Security & Ethical Boundaries

### What Agents Will NOT Do
- ❌ Attack targets outside the authorized scope — hard stop, no override
- ❌ Operate outside the engagement time window
- ❌ Store credentials in plaintext
- ❌ Exfiltrate real client data (proof-of-access patterns only)
- ❌ Deploy real malware (custom PoCs only)
- ❌ Leave persistent backdoors beyond engagement scope
- ❌ Execute DoS/DDoS unless explicitly authorized in ROE
- ❌ Perform social engineering unless explicitly authorized
- ❌ Publish or share exploit code publicly

### Authorization dependency
- All offensive actions require the operator to confirm authorization
- The scope check hook validates targets but relies on `authorized_scope.json` being correctly configured
- There is no cryptographic signing or verification of the scope document — it is trust-based

---

## Accuracy Caveats

- **CVSS scores are computed by the LLM** — always cross-reference against NVD for published CVEs
- **ATT&CK mappings are best-effort** — the LLM selects techniques based on pattern matching, not deterministic classification
- **YARA/Sigma rules are generated, not tested** — always validate against known samples before deployment
- **MCP API responses depend on data freshness** — Shodan data may be weeks old, VirusTotal results depend on scanner updates
- **False negatives are possible** — the IOC extractor and session sanitizer use regex patterns that cannot catch every format variation
