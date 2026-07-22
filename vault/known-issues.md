# ⚠️ Known Issues & Limitations

> Tracking known issues, limitations, and open questions for the cyber-agents project.

---

## Current Issues

### Platform & Environment

| Issue | Platform | Workaround |
|-------|----------|------------|
| **macOS system Python is 3.9** | macOS | Use `python3.12` via Homebrew or activate a venv |
| **PEP 668 blocks global pip installs** | macOS (Homebrew Python) | Use `python3 -m venv .venv && .venv/bin/pip install -e .` |
| **Port 8088 conflict** | All | AegisSIEM daemon and any legacy Flask dashboard both claim 8088 — stop the legacy service first |
| **OpenEye Pi deployment** | ARM Linux (Pi) | `dlib`, `torch`, `YOLO` unavailable on Pi — use `requirements-pi.txt` which excludes these |
| **AI-for-Survival Pi deployment** | ARM Linux (Pi) | `chromadb`, `sentence-transformers` unavailable — RAG functionality degrades to keyword search |

### Tool Dependencies

- **Nmap SYN scans require root/sudo** — TCP connect scan (`-sT`) works without root but is slower and noisier
- **Metasploit requires PostgreSQL** — `msfdb init` must be run before database features work
- **YARA Python bindings** require separate installation (`pip3 install yara-python`) from the YARA CLI
- **Volatility 3** plugin availability varies by OS — not all profiles available for all OS versions
- **Ollama must be running** for `/analyze --depth full` and Log Analyst agent — if it's not up, analysis falls back to local pattern matching only

### Hook Behavior

- **Scope check is regex-based** — it extracts IPs/domains from command strings but cannot parse all possible tool argument formats; obfuscated or variable-indirected targets bypass validation
- **IOC extractor has false positives** — MD5 hashes (32 hex chars) match many non-hash strings in code output
- **Session sanitizer processes text only** — binary data in session context is not scanned for credentials
- **Hooks are global** — all 5 hooks fire in every Claude Code session, not just cybersecurity contexts; async hooks (`threat-watcher`, `ioc-extractor`, `ecosystem-publisher`) run in background so overhead is minimal

### Platform Gaps

- **Windows agent execution**: Agents and skills are optimized for macOS/Linux operator workstations. Windows-native workflows (PowerShell, WMI-based) are documented as analysis targets, not operator tools.
- **Cloud environments**: No dedicated cloud security agent (AWS, GCP, Azure) — planned for future release
- **Container security**: No Docker/Kubernetes-specific scanning workflows yet

### Detection Rule Coverage

- Sigma rules target **Sysmon** and **Windows Security** event logs primarily — coverage for Linux `auditd` and macOS `unified log` is limited
- YARA rule templates focus on **PE** (Windows) and **PHP webshells** — ELF, Mach-O templates planned
- Snort/Suricata rule generation in `/hunt` is basic — complex protocol dissection rules require manual tuning

### Agent Coordination

- No automated inter-agent communication protocol — delegation is manual via operator
- No session persistence between agent invocations — campaign state must be tracked in vault files manually
- Purple team coordination (red ↔ blue) requires operator to relay outputs between agents

---

## Open Questions

1. **MCP Integration**: Should agents use MCP servers for live tool execution (Nmap, Metasploit) or continue with Bash-based invocation?
2. **Evidence Storage**: Should evidence files (PCAPs, memory dumps, disk images) be referenced in the vault or stored alongside it?
3. **Rule Testing Infrastructure**: Should we include a Docker-based lab environment for testing YARA/Sigma rules against known samples?
4. **Authorization Workflow**: The scope document is trust-based with no cryptographic signing — should we add a signed authorization token system?
5. **Reporting Templates**: Standardize on Markdown only, or support multiple export formats (PDF, HTML, JSON)?
6. **Ollama Model Selection**: `qwen2.5-coder` is used for log analysis — should threat hunter and incident responder also route through Ollama for offline environments?

---

## Fixed Issues

| Date | Issue | Resolution |
|------|-------|-----------|
| 2026-03-24 | Python version inconsistency across ecosystem projects | Harmonized all projects to `>=3.10`; OpenEye updated to `>=3.10` (3.11+ recommended) |
| 2026-03-24 | `appEcosystem` install failure on fresh systems | Entry point and import path fixed in `pyproject.toml` |
| 2026-03-24 | `cyber-harness` install broken by `*.egg-info` remnants | Added cleanup step to installation workflow |
| 2026-03-27 | Agents/skills/commands not available outside CybersecurityTeam project | Symlinked to `~/.claude/` for global availability in all Claude Code sessions |
| 2026-03-27 | Hooks only active in project-level config | Moved to `~/.claude/settings.json` for global activation |
| 2026-03-27 | AegisSIEM and ecosystem MCP servers not registered | Added to `~/.claude.json` via `claude mcp add` |
