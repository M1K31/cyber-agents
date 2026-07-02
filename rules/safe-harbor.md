# Rule: Safe Harbor — Rules of Engagement (ROE)

> **Enforcement Level**: MANDATORY — ALL agents (Red and Blue Team) MUST refuse any operation targeting infrastructure outside the explicitly authorized scope. There are **zero exceptions** to this rule without written operator override.

---

## Purpose

This rule establishes the Rules of Engagement (ROE) framework that governs all agent operations. It ensures that offensive testing is confined to authorized targets and that defensive agents only access data within their mandate. Violation of these rules may constitute unauthorized access under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, or equivalent local legislation.

---

## 1. Scope Definition

### 1.1 Scope Document Structure

Every engagement MUST have a scope document before any operations begin. Agents MUST refuse to operate without one.

```markdown
## Engagement Scope — [Engagement Name]

| Field | Value |
|-------|-------|
| **Engagement ID** | ENG-YYYY-NNN |
| **Client** | Organization Name |
| **Authorization Date** | YYYY-MM-DD |
| **Start Date** | YYYY-MM-DD HH:MM UTC |
| **End Date** | YYYY-MM-DD HH:MM UTC |
| **Authorizing Contact** | Name, Title, Email, Phone |
| **Emergency Contact** | Name, Phone (24/7) |
| **Engagement Type** | External / Internal / Web App / Social Engineering / Physical |

### In-Scope Targets

| Type | Value | Notes |
|------|-------|-------|
| IP Range | 10.0.0.0/24 | Internal servers |
| IP Range | 192.168.1.0/24 | DMZ |
| Domain | *.target.example.com | All subdomains |
| Domain | api.target.example.com | API endpoints only |
| URL | https://app.target.example.com/* | Web application |
| Host | SRV-WEB01 (10.0.0.50) | Specific server |

### Out-of-Scope (EXCLUDED)

| Type | Value | Reason |
|------|-------|--------|
| IP | 10.0.0.1 | Production gateway — do not touch |
| IP Range | 10.0.1.0/24 | Third-party hosted infrastructure |
| Domain | mail.target.example.com | Production email — business critical |
| Service | Any DoS/DDoS testing | Not authorized |
| Action | Social engineering of C-suite | Not authorized |

### Permitted Actions

- [ ] Network scanning (passive)
- [ ] Network scanning (active — noise level ≤ 3)
- [ ] Vulnerability scanning
- [ ] Exploitation of discovered vulnerabilities
- [ ] Post-exploitation and lateral movement
- [ ] Credential harvesting
- [ ] Data exfiltration (proof-of-access only)
- [ ] Social engineering (email phishing)
- [ ] Physical security testing
- [ ] Denial of service testing

### Restrictions

- Testing hours: [e.g., 22:00-06:00 UTC only / anytime]
- Maximum concurrent sessions: [e.g., 5]
- Production data handling: [e.g., no real data exfiltration]
- Notification requirement: [e.g., email client POC before exploitation]
```

### 1.2 Scope Validation Protocol

```
RULE: Before EVERY operation, agents MUST validate the target is in scope.

VALIDATION PROCEDURE:
1. EXTRACT target identifier (IP, domain, URL, hostname)
2. CHECK against the in-scope list:
   a. IP address → match against authorized CIDR ranges
   b. Domain → match against authorized domain patterns (supports wildcards)
   c. URL → match against authorized URL prefixes
   d. Hostname → match against authorized host list
3. CHECK against the out-of-scope exclusion list
4. If target is NOT in the in-scope list → REFUSE and report
5. If target IS in the out-of-scope list → REFUSE and report
6. If target is in-scope AND not excluded → PROCEED

VALIDATION EXAMPLES:
  Target: 10.0.0.50      → In-scope (matches 10.0.0.0/24) ✅
  Target: 10.0.1.50      → Out-of-scope (matches excluded 10.0.1.0/24) ❌
  Target: 10.0.0.1       → Excluded (specific exclusion) ❌
  Target: web.target.example.com → In-scope (matches *.target.example.com) ✅
  Target: mail.target.example.com → Excluded (specific exclusion) ❌
  Target: other.example.com → Out-of-scope (not in scope list) ❌
```

---

## 2. Enforcement Directives

### 2.1 Hard Stops (Non-Negotiable)

```
The following actions MUST trigger an immediate HARD STOP.
No override is possible without a new, signed scope amendment.

HARD STOP TRIGGERS:
1. Target IP/domain is not in the authorized scope document
2. Target is explicitly listed in the out-of-scope exclusion list
3. Engagement window has expired (current time > end date)
4. No scope document has been provided in the current session
5. Operator requests denial-of-service testing when not authorized
6. Operator requests social engineering when not authorized
7. Discovery of systems belonging to unrelated third parties

HARD STOP RESPONSE:
  ⛔ OPERATION REFUSED — Target [X] is outside the authorized engagement scope.
  
  Scope document: [engagement ID]
  Authorization: [date range]
  In-scope targets: [list]
  Requested target: [X]
  Reason: [not in scope / explicitly excluded / engagement expired]
  
  To proceed, provide an updated scope document with [X] included.
```

### 2.2 Soft Stops (Require Confirmation)

```
The following actions trigger a SOFT STOP — the agent pauses and requests
operator confirmation before proceeding.

SOFT STOP TRIGGERS:
1. Scan noise level exceeds what's documented as approved (see rules/opsec.md)
2. Discovery of a new subnet or domain not explicitly listed but potentially
   within the client's infrastructure
3. Exploitation would affect a shared service (DNS, DHCP, AD)
4. Credentials discovered that provide access to out-of-scope systems
5. Action could cause service degradation (heavy scanning, resource-intensive exploits)

SOFT STOP RESPONSE:
  ⚠️ CONFIRMATION REQUIRED — This action [description] may [risk description].
  
  Details: [specifics]
  Risk: [potential impact]
  
  Options:
  1. PROCEED — Execute with stated risk accepted
  2. MODIFY — Adjust parameters to reduce risk
  3. ABORT — Cancel this action
  
  Please confirm your choice.
```

---

## 3. Adjacent Discovery Protocol

```
RULE: When in-scope operations reveal adjacent (out-of-scope) systems,
agents MUST follow this protocol.

SCENARIO: During authorized scanning of 10.0.0.0/24, the agent discovers
that 10.0.0.50 has routes to 10.0.2.0/24 (not in scope).

PROTOCOL:
1. DOCUMENT the discovery:
   - Source system (in-scope): 10.0.0.50
   - Adjacent system(s): 10.0.2.0/24
   - Discovery method: route table, ARP cache, DNS, etc.
   - Timestamp

2. DO NOT enumerate, scan, or probe the adjacent systems

3. REPORT to the operator:
   "Adjacent network 10.0.2.0/24 discovered via route table on 10.0.0.50.
    This network is NOT in the current engagement scope.
    No probing has been performed.
    To include this in the engagement, provide an updated scope document."

4. CONTINUE operations within the authorized scope only

5. Record in vault for the final report as an "Out-of-Scope Observation"
```

---

## 4. Temporal Constraints

```
RULE: Agents MUST enforce time-based restrictions.

1. ENGAGEMENT WINDOW:
   - All operations MUST occur within the authorized date/time range
   - If current time > engagement end date → REFUSE all offensive operations
   - If current time < engagement start date → REFUSE, note "Engagement not yet active"

2. TESTING HOURS (if restricted):
   - Check current UTC time against permitted testing hours
   - If outside testing hours → queue the action and notify operator
   - Exception: Passive OSINT (Level 1) is always permitted

3. EMERGENCY STOP:
   - If the client invokes the emergency stop (code word or direct contact):
     a. CEASE all active operations immediately
     b. Terminate all active sessions and C2 callbacks
     c. Document the stop with timestamp and reason
     d. Do NOT resume until explicit re-authorization
```

---

## 5. Third-Party and Shared Infrastructure

```
RULE: Agents MUST exercise extreme caution with shared infrastructure.

CLOUD SERVICES:
- Shared hosting (AWS, Azure, GCP): Only test the CLIENT'S resources
  identified by specific resource IDs, IPs, or domain names
- Never scan cloud provider infrastructure or other tenants
- Verify cloud targets via resource tags, account IDs, or DNS verification

CDN / WAF / REVERSE PROXIES:
- Identify the actual backend server before exploitation
- Do not attack the CDN/WAF infrastructure itself (Cloudflare, Akamai, etc.)
- Document CDN/WAF presence in reconnaissance findings

SHARED SERVICES:
- Active Directory: Authorized actions only (no domain-wide password spray
  unless explicitly permitted)
- DNS servers: Query only, no zone transfer attempts unless authorized
- Email: No mass phishing unless social engineering is in scope
```

---

## 6. De-Escalation Protocol

```
If an operation causes unintended impact:

1. STOP the operation immediately
2. ASSESS the impact:
   - Service disruption?
   - Data loss or corruption?
   - Alert triggered to SOC/Blue Team?
3. NOTIFY the client emergency contact if:
   - Any production service is disrupted
   - Any data loss or corruption is suspected
   - The incident requires immediate remediation
4. DOCUMENT everything:
   - What action caused the impact
   - When it occurred (UTC)
   - What systems were affected
   - What remediation was performed
5. DETERMINE if the engagement should pause
6. UPDATE vault/incidents/ with the de-escalation record
```
