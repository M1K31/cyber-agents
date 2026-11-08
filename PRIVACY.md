# Privacy Policy

**Product**: Cyber Agents (`cyber-agents` & `AegisSIEM_Daemon`)  
**Owner & Maintainer**: Smart Industries LLC (Mikel Smart)  
**Effective Date**: November 2026  

---

## 1. Scope & Architecture
Cyber Agents (`cyber-agents`) is a **local-first cybersecurity agent harness and threat-analysis daemon** engineered by **Smart Industries LLC** (Mikel Smart). It runs locally on operator-controlled hardware (macOS, Linux) and integrates with `appEcosystem`, `AegisSIEM`, `AI-for-Survival`, and `OpenEye`.

## 2. Data Collection & Local Storage
All daemon state, threat records, attacker profiles, approval checkpoints, and audit logs remain **on your local machine** by default:
- **Local State Database**: Threat detections, syslog events, blocked IPs, and approval checkpoints are stored locally in SQLite (`~/.aegissiem/daemon.db` or configured state directory).
- **Credential Hygiene & Redaction**: Installed pre-execution and post-execution hooks (`credential-leak-guard.js`, `output-credential-redactor.js`, `pre-command-scope-check.js`) run locally to prevent secrets, API keys, and out-of-scope targets from leaking into command arguments, outputs, or LLM prompts.
- **Authentication Secrets**: Inter-service HMAC secrets (`~/.config/ecosystem/secret.env`) and optional cloud provider keys (`~/.config/ecosystem/provider_keys.json`) are stored locally with owner-only (`0600`) permissions and are never transmitted to Smart Industries LLC.

## 3. External Network Communications (Opt-In Only)
Cyber Agents includes **no** telemetry beacons, analytics SDKs, or third-party tracking:
1. **Local-First AI Routing**: By default, security analysis uses a local Ollama model (`http://localhost:11434`) with cloud fallback disabled (`allow_cloud_fallback: false`). Cloud LLM providers (Anthropic, OpenAI, Google Gemini) are invoked only when explicitly enabled by the administrator in the shared Ecosystem AI Profile.
2. **Optional Threat Intelligence MCP Servers**: Integrations with VirusTotal, Shodan, AbuseIPDB, NVD, or Slack run only when the operator explicitly configures their own API credentials and invokes those tools within authorized scope.
3. **Authorized Scope Enforcement**: Active reconnaissance or defensive verification tools operate strictly within operator-defined authorized network scopes.

## 4. Policy Engine, Provisional Containment & Step-Up Auth
- **Fail-Closed Policy Gating**: Every model-proposed mitigation or scanning request is evaluated by `ecosystem-policy` before execution. The model can never execute actions directly.
- **Provisional Containment with TTL Rollback**: Time-limited containment actions (e.g. temporary router firewall block) apply immediately with automated notification, subject to an automatic time-to-live (TTL) rollback timer. If an administrator does not explicitly confirm the action, it automatically reverts.
- **Step-Up Verification**: Permanent remediation actions or policy overrides require operator step-up authentication using a 6-digit Time-Based One-Time Password (TOTP).
- **Emergency Freeze**: Cyber Agents strictly respects `ecosystem.freeze` kill-switch directives from the mesh. Freeze prevents any **new** mutating or scanning action from starting; an action already in flight when Freeze arrives (for example a router block mid-SSH) may complete, but no further actions are taken until Freeze is lifted.

## 5. Data Retention & Erasure
Operators retain full custody of all local files and databases. All local daemon state lives under `~/.aegissiem-daemon/` (overridable via `CYBER_HARNESS_STATE_DIR`): the SQLite database `aegissiem.db`, `config.yml`, the policy state `policy_state.json`, and the `vault/threat-data/` directory. Shared step-up credentials and policy keys default to `~/.config/ecosystem/` (overridable via `ECOSYSTEM_POLICY_KEY_DIR`). Stopping the daemon and removing those paths permanently deletes all locally stored threat records, logs and step-up state.

## 6. Contact Information
For privacy inquiries or security disclosures, contact **Smart Industries LLC** (Owner: **Mikel Smart**).

