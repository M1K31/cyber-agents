# Rule: Data Handling

> **Enforcement Level**: MANDATORY — All agents MUST automatically redact sensitive data from output and memory. No exceptions.

---

## Purpose

This rule defines how all agents (Red and Blue Team) must handle sensitive data encountered during operations. Agents must proactively identify and redact personally identifiable information (PII), credentials, cryptographic keys, and other sensitive material from all output, reports, and stored artifacts. This protects the client, the operator, and any individuals whose data may be incidentally exposed.

---

## 1. Sensitive Data Classification

### Tier 1 — CRITICAL (Auto-Redact Immediately)

These patterns MUST be detected and redacted in **all agent output** without exception.

| Data Type | Detection Pattern | Redaction Format |
|-----------|------------------|-----------------|
| **Passwords** | Plaintext after `password=`, `passwd:`, `pass:`, credential dumps | `[REDACTED-PASSWORD]` |
| **Private Keys** | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | `[REDACTED-PRIVATE-KEY type=RSA\|EC\|...]` |
| **API Keys/Tokens** | `AKIA[A-Z0-9]{16}` (AWS), `ghp_[a-zA-Z0-9]{36}` (GitHub), `sk-[a-zA-Z0-9]{48}` (OpenAI), Bearer tokens | `[REDACTED-API-KEY provider=AWS\|GitHub\|...]` |
| **Credit Card Numbers** | `\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b` (Luhn-valid) | `[REDACTED-CC last4=XXXX]` |
| **SSN / National ID** | `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b` (US SSN pattern) | `[REDACTED-SSN]` |
| **NTLM Hashes** | `[a-fA-F0-9]{32}` in credential dump context | `[REDACTED-NTLM user=USERNAME]` |
| **Kerberos Tickets** | `krbtgt`, TGT/TGS base64 blobs | `[REDACTED-KERBEROS-TICKET]` |
| **Session Cookies** | `Set-Cookie:` with session/auth tokens | `[REDACTED-SESSION-COOKIE name=COOKIENAME]` |
| **Connection Strings** | `jdbc:`, `mongodb://`, `postgres://` with embedded credentials | `[REDACTED-CONNSTRING type=postgres\|mongo\|...]` |

### Tier 2 — SENSITIVE (Redact in Reports, Retain in Evidence)

These MUST be redacted in human-readable reports but MAY be retained in encrypted evidence stores.

| Data Type | Detection Pattern | Redaction Format |
|-----------|------------------|-----------------|
| **Email Addresses** | Standard email regex | `[REDACTED-EMAIL domain=example.com]` |
| **Phone Numbers** | International/domestic phone patterns | `[REDACTED-PHONE]` |
| **Physical Addresses** | Street address patterns | `[REDACTED-ADDRESS]` |
| **Employee Names** | Names from AD dumps, email headers | `[REDACTED-NAME role=admin\|user]` |
| **Internal Hostnames** | FQDN patterns specific to the client | Use anonymized labels: `HOST-01`, `SRV-DB-A` |
| **Internal IP Addresses** | RFC 1918 ranges in final client-facing reports | May be retained if client approves |

### Tier 3 — OPERATIONAL (Handle Per Engagement Agreement)

| Data Type | Handling |
|-----------|----------|
| **File hashes** (SHA-256, MD5) | Retain — these are non-reversible identifiers |
| **IP addresses** (external) | Retain — needed for IOC reporting |
| **Domain names** (external) | Retain — needed for IOC reporting |
| **MITRE ATT&CK IDs** | Retain — non-sensitive framework references |
| **Tool/service versions** | Retain — needed for vulnerability assessment |

---

## 2. Auto-Redaction Procedures

### 2.1 Real-Time Output Redaction

```
RULE: Before displaying ANY output to the operator, agents MUST:

1. SCAN the output for Tier 1 patterns
2. REPLACE all matches with the corresponding [REDACTED-*] token
3. LOG the redaction event (what was redacted, not the redacted value):
   "Redacted 3 instances of REDACTED-PASSWORD from secretsdump output"
4. DISPLAY the sanitized output

IMPLEMENTATION:
  Apply regex-based pattern matching for each Tier 1 data type.
  Process output line-by-line before rendering.
  If a pattern match confidence is < 80%, flag for operator review
  rather than auto-redacting (to avoid redacting legitimate data).
```

### 2.2 Report Redaction

```
RULE: All reports stored in vault/ MUST apply Tier 1 AND Tier 2 redaction.

PROCEDURE:
1. Generate the raw report with full findings
2. Apply Tier 1 auto-redaction (all sensitive patterns)
3. Apply Tier 2 redaction (PII, internal identifiers)
4. Store the REDACTED version in vault/
5. If unredacted evidence is needed for legal/forensic purposes:
   a. Store in a SEPARATE encrypted container
   b. Label clearly: "UNREDACTED — CONTAINS SENSITIVE DATA"
   c. Restrict access per the engagement's data handling agreement
```

### 2.3 Memory/Context Redaction

```
RULE: Agents MUST NOT retain sensitive data in their operational context
beyond the immediate task that requires it.

PROCEDURE:
1. Process sensitive data (e.g., parse credential dump)
2. Extract ONLY the metadata needed (username, access level, hash type)
3. Discard the raw sensitive values from working context
4. Report findings using redacted placeholders
5. Reference the encrypted evidence store for full details

EXAMPLE:
  Input:  "Administrator:500:aad3b435b51404ee:e19ccf75ee54e06b7e9..."
  Retain: "User 'Administrator' (RID 500) — NTLM hash captured"
  Discard: The actual hash value from context
  Report: "[REDACTED-NTLM user=Administrator] — Domain Admin credentials harvested"
```

---

## 3. Credential-Specific Handling

### 3.1 Discovered Credentials Pipeline

```
STEP 1: DETECT credentials in tool output
  - Monitor output from: secretsdump, mimikatz, hashdump, LaZagne,
    config files, database dumps, web application responses

STEP 2: CLASSIFY credential type
  - Plaintext password → Tier 1 CRITICAL
  - Password hash (NTLM, NTLMv2, Kerberoast) → Tier 1 CRITICAL
  - SSH private key → Tier 1 CRITICAL
  - API key / token → Tier 1 CRITICAL
  - Session cookie → Tier 1 CRITICAL

STEP 3: RECORD metadata only
  - Username / account name
  - Credential type (plaintext / hash / key / token)
  - Source system
  - Privilege level (admin / user / service)
  - Timestamp of discovery

STEP 4: SECURE the raw credential
  - Encrypt and store in engagement evidence container
  - Never store in plaintext, shell history, or unencrypted files

STEP 5: REPORT using redacted format
  "Credential harvested: [REDACTED-PASSWORD user=svc_backup type=plaintext]
   Source: SAM database on SRV-DC01
   Privilege: Domain Admin (member of Domain Admins group)
   Timestamp: 2026-03-17T15:30:00Z"
```

### 3.2 Proof-of-Access Pattern

```
RULE: When demonstrating access, use proof-of-access artifacts
instead of exfiltrating real data.

ACCEPTABLE PROOF:
  - `whoami /all` output → shows current user and group membership
  - `hostname` → confirms target system identity
  - Directory listing of sensitive share → proves access without reading files
  - `SELECT COUNT(*) FROM users;` → proves DB access without dumping data
  - Screenshot of admin panel → proves access without extracting data

PROHIBITED:
  - Dumping entire database tables with real user data
  - Copying real documents, financial records, or PII
  - Reading email contents
  - Downloading real backups or archives
```

---

## 4. Data Retention & Destruction

```
RULE: All engagement data MUST follow a defined lifecycle.

RETENTION SCHEDULE:
  - Active engagement: Full data retained in encrypted evidence store
  - Post-engagement (0-30 days): Retained for report finalization and Q&A
  - Post-engagement (30-90 days): Retained if legal hold or compliance requires
  - Post-engagement (90+ days): DESTROY unless contractually obligated to retain

DESTRUCTION PROCEDURE:
  1. Verify all deliverables are finalized and accepted by client
  2. Verify no active legal holds
  3. Secure delete all engagement data:
     - `shred -vfz -n 3 <file>` (Linux)
     - `srm -sz <file>` (macOS, if available)
     - Or: overwrite with random data, then delete
  4. Destroy encrypted containers (delete keyfile + container)
  5. Clear relevant shell history: `history -c && history -w`
  6. Document destruction in engagement closure record
  7. Confirm with client that data has been destroyed
```

---

## 5. Compliance Mapping

| Requirement | Regulation | How This Rule Addresses It |
|-------------|-----------|---------------------------|
| PII protection | GDPR Art. 5, CCPA §1798.100 | Auto-redaction of Tier 1 & 2 data |
| Data minimization | GDPR Art. 5(1)(c) | Proof-of-access pattern; metadata-only retention |
| Storage limitation | GDPR Art. 5(1)(e) | Defined retention schedule with destruction procedure |
| Security of processing | GDPR Art. 32 | Encrypted evidence stores, secure deletion |
| Breach notification | GDPR Art. 33-34 | De-escalation protocol in safe-harbor.md |
| Evidence integrity | NIST SP 800-86 | SHA-256 hashing, chain-of-custody in incident-responder |
| Credential protection | PCI DSS Req. 8 | Encrypted credential storage, no plaintext retention |
