"""WP5 Triage Action-Loop Engine & Authority Handoff Profile Generator.

Orchestrates structured threat triage using the local Model Forge / Ollama
analyst model, parses `action-proposal.v1` proposals, enforces sensitive
PII/PHI/financial data redaction, classifies hardware/network disruption risk,
and generates NIST SP 800-61 aligned forensic handoff profiles.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any

from .redaction import redact_sensitive_data, redact_structure

KNOWN_TRIAGE_CAPABILITIES: frozenset[str] = frozenset({
    "threat_intel.lookup_ioc",
    "containment.block_ip",
    "containment.quarantine_device",
    "security.honeypot_status",
    "scan.request",
})

ALLOWED_ACTION_CLASSES: frozenset[str] = frozenset({
    "observe",
    "investigate",
    "contain",
    "remediate",
    "data_release",
    "system_change",
})

_MITRE_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)

_DISRUPTIVE_KEYWORDS: tuple[str, ...] = (
    "ddos",
    "dos attack",
    "syn flood",
    "udp flood",
    "http flood",
    "ransomware",
    "wiper",
    "destructive",
    "router compromise",
    "firmware tamper",
    "arp spoof",
    "arp poison",
    "bgp hijack",
    "deauth flood",
    "service unavailable",
    "network outage",
    "hardware failure",
    "brute force flood",
    "credential stuffing flood",
)


def extract_mitre_techniques(text: str) -> list[str]:
    """Return deduplicated MITRE ATT&CK technique IDs in order of appearance."""
    seen: set[str] = set()
    out: list[str] = []
    for match in _MITRE_RE.findall(text or ""):
        if match not in seen:
            seen.add(match)
            out.append(match)
    return out


def classify_disruption(
    text: str,
    *,
    threat_type: str = "",
    severity: str = "",
    verdict: str = "",
) -> bool:
    """Return True when a critical threat threatens hardware or network availability.

    Critical disruptive threats qualify for automatic provisional containment
    with a rollback timer; non-disruptive threats wait for operator confirmation.
    """
    sev = str(severity or "").strip().lower()
    if sev != "critical" and str(verdict or "").strip().lower() != "malicious":
        return False
    combined = f"{threat_type} {text}".lower()
    return any(kw in combined for kw in _DISRUPTIVE_KEYWORDS)


def parse_triage_proposals(
    text: str,
    *,
    known_capabilities: set[str] | frozenset[str] | None = KNOWN_TRIAGE_CAPABILITIES,
) -> list[dict[str, Any]]:
    """Extract and validate `action-proposal.v1` proposals from analyst output.

    Uses `ecosystem_client.contracts.parse_proposals` when available, with a
    strict fail-closed fallback for isolated environments. Returns a list of
    JSON-serializable proposal dicts; returns `[]` if no valid JSON proposal
    block is present.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    # Try fenced JSON blocks first (last block usually holds the final proposals)
    candidates: list[str] = [m.group(1).strip() for m in _JSON_FENCE_RE.finditer(text)]
    if not candidates:
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            candidates.append(stripped)

    if not candidates:
        return []

    raw_json_str = candidates[-1]

    # Prefer canonical ecosystem_client parser when installed
    try:
        from ecosystem_client.contracts import parse_proposals as _canonical_parse

        parsed = _canonical_parse(
            raw_json_str,
            known_capabilities=set(known_capabilities) if known_capabilities is not None else None,
        )
        out: list[dict[str, Any]] = []
        for p in parsed:
            conf = float(getattr(p, "confidence", 1.0))
            if math.isnan(conf) or math.isinf(conf) or not (0.0 <= conf <= 1.0):
                continue
            out.append({
                "action": str(p.action),
                "action_class": str(p.action_class),
                "target": p.target,
                "parameters": dict(getattr(p, "parameters", {}) or {}),
                "rationale": str(getattr(p, "rationale", "") or ""),
                "confidence": conf,
            })
        return out
    except ImportError:
        pass
    except Exception:
        # Unusable model output — fail closed with zero proposals
        return []

    # Strict fallback parser when ecosystem_client.contracts is not installed
    try:
        payload = json.loads(raw_json_str)
    except Exception:
        return []

    items = payload.get("proposals") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return []

    proposals: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        action = item.get("action")
        action_class = item.get("action_class")
        target = item.get("target")
        parameters = item.get("parameters")
        rationale = item.get("rationale")
        if (
            not isinstance(action, str)
            or not action.strip()
            or not isinstance(action_class, str)
            or action_class not in ALLOWED_ACTION_CLASSES
            or target is None
            or not isinstance(parameters, dict)
            or not isinstance(rationale, str)
        ):
            continue
        if known_capabilities is not None and action not in known_capabilities:
            continue
        conf_raw = item.get("confidence", 1.0)
        try:
            conf = float(conf_raw)
        except (TypeError, ValueError):
            continue
        if math.isnan(conf) or math.isinf(conf) or not (0.0 <= conf <= 1.0):
            continue
        proposals.append({
            "action": action,
            "action_class": action_class,
            "target": target,
            "parameters": parameters,
            "rationale": rationale,
            "confidence": conf,
        })
    return proposals


def build_authority_handoff_profile(
    run_record: dict[str, Any],
    *,
    output_format: str = "json",
) -> dict[str, Any] | str:
    """Build a NIST SP 800-61 aligned forensic handoff profile for review or authorities.

    Re-applies PII/PHI/financial redaction to all text fields and attaches a
    deterministic SHA-256 evidence digest for chain-of-custody verification.
    """
    redacted_record, extra_redactions = redact_structure(run_record)
    merged_redactions = dict(redacted_record.get("redaction_summary") or {})
    for cat, count in extra_redactions.items():
        merged_redactions[cat] = merged_redactions.get(cat, 0) + count

    evidence_payload = {
        "triage_run_id": redacted_record.get("run_id") or redacted_record.get("id"),
        "threat_id": redacted_record.get("threat_id"),
        "source_ip": redacted_record.get("source_ip"),
        "severity": redacted_record.get("severity"),
        "verdict": redacted_record.get("verdict"),
        "disruptive_critical": bool(redacted_record.get("disruptive_critical")),
        "mitre_techniques": list(redacted_record.get("mitre_techniques") or []),
        "summary": redacted_record.get("summary") or "",
        "redacted_event": redacted_record.get("redacted_event") or "",
        "proposals": list(redacted_record.get("proposals") or []),
        "triage_timeline": list(redacted_record.get("triage_timeline") or []),
    }
    canonical = json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()

    profile: dict[str, Any] = {
        "schema_version": "aegissiem.handoff.v1",
        "standard": "NIST SP 800-61 Rev. 2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "incident": evidence_payload,
        "privacy_protection": {
            "pii_phi_financial_redacted": True,
            "redaction_summary": merged_redactions,
        },
        "chain_of_custody": {
            "collected_by": "cyber-agents/aegissiem_daemon",
            "model": redacted_record.get("model") or "unknown",
            "provider": redacted_record.get("provider") or "unknown",
            "recorded_at": redacted_record.get("created_at") or datetime.now(timezone.utc).isoformat(),
            "evidence_sha256": digest,
        },
    }

    if output_format.lower() == "markdown":
        techniques = ", ".join(evidence_payload["mitre_techniques"]) or "None mapped"
        proposals_md = "\n".join(
            f"- **{p.get('action')}** (`{p.get('action_class')}`) → `{p.get('target')}` "
            f"(confidence: {p.get('confidence', 0):.2f}): {p.get('rationale', '')}"
            for p in evidence_payload["proposals"]
        ) or "- No automated containment proposals."
        redaction_md = ", ".join(
            f"{k}: {v}" for k, v in sorted(merged_redactions.items())
        ) or "None detected"
        return (
            f"# Incident Forensic Handoff Profile\n\n"
            f"- **Run ID:** `{evidence_payload['triage_run_id']}`\n"
            f"- **Generated (UTC):** {profile['generated_at_utc']}\n"
            f"- **Standard:** {profile['standard']}\n"
            f"- **Threat ID:** `{evidence_payload['threat_id']}`\n"
            f"- **Source IP:** `{evidence_payload['source_ip'] or 'unknown'}`\n"
            f"- **Severity / Verdict:** `{evidence_payload['severity']}` / `{evidence_payload['verdict']}`\n"
            f"- **Disruptive Critical Threat:** `{evidence_payload['disruptive_critical']}`\n"
            f"- **MITRE ATT&CK Techniques:** {techniques}\n\n"
            f"## Analyst Summary\n\n{evidence_payload['summary']}\n\n"
            f"## Proposed & Executed Actions\n\n{proposals_md}\n\n"
            f"## Redacted Telemetry Evidence\n\n```text\n{evidence_payload['redacted_event']}\n```\n\n"
            f"## Privacy & Chain of Custody\n\n"
            f"- **PII / PHI / Financial Redaction Applied:** Yes ({redaction_md})\n"
            f"- **Collected By:** `{profile['chain_of_custody']['collected_by']}`\n"
            f"- **Model / Provider:** `{profile['chain_of_custody']['model']}` / `{profile['chain_of_custody']['provider']}`\n"
            f"- **Evidence SHA-256:** `{digest}`\n"
        )

    return profile


def build_triage_timeline_steps(
    *,
    verdict: str,
    disruptive_critical: bool,
    proposals: list[dict[str, Any]],
    redaction_summary: dict[str, int],
    model: str,
) -> list[dict[str, Any]]:
    """Build a structured triage timeline for UI display and archival."""
    now = datetime.now(timezone.utc).isoformat()
    steps: list[dict[str, Any]] = [
        {
            "step": 1,
            "stage": "privacy_redaction",
            "status": "completed",
            "timestamp": now,
            "detail": (
                f"Redacted sensitive fields: {redaction_summary}"
                if redaction_summary
                else "Verified no raw PII/PHI/financial fields in telemetry."
            ),
        },
        {
            "step": 2,
            "stage": "agent_triage",
            "status": "completed",
            "timestamp": now,
            "detail": (
                f"Local analyst ({model}) verdict: {verdict}; "
                f"disruptive_critical={disruptive_critical}; "
                f"proposals={len(proposals)}"
            ),
        },
    ]
    for idx, prop in enumerate(proposals, start=3):
        is_contain = prop.get("action_class") == "contain"
        recommended_gate = (
            "auto_provisional_with_timer"
            if (is_contain and disruptive_critical)
            else ("require_operator_confirmation" if is_contain else "observe_allowed")
        )
        steps.append({
            "step": idx,
            "stage": "proposal",
            "action": prop.get("action"),
            "action_class": prop.get("action_class"),
            "target": prop.get("target"),
            "recommended_gate": recommended_gate,
            "status": "proposed",
            "timestamp": now,
            "detail": prop.get("rationale") or "",
        })
    return steps
