"""Unit tests for WP5: cyber-agents action-loop triage, redaction, and authority handoff."""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from daemon.agent_prompts import build_triage_system_prompt, load_agent_prompt
from daemon.db import Database
from daemon.ecosystem_commands import DaemonCommandHandlers
from daemon.models import Severity, ThreatEvent
from daemon.redaction import redact_sensitive_data
from daemon.triage_engine import (
    build_authority_handoff_profile,
    classify_disruption,
    extract_mitre_techniques,
    parse_triage_proposals,
)


def _run(coro):
    return asyncio.run(coro)


def _ctx(params: dict):
    return SimpleNamespace(capability="security.triage_threat", parameters=params)


class FakeModel:
    def __init__(self, reply: str):
        self.reply = reply
        self.seen_prompts: list[str] = []

    async def __call__(self, prompt: str, *, local_only: bool = False):
        assert local_only is True
        self.seen_prompts.append(prompt)
        return self.reply, "heretic-llama3.1-8b-q4", "ollama"


def test_agent_prompt_loader_and_traversal_guard():
    ir = load_agent_prompt("incident-responder")
    assert "PICERL" in ir
    assert "---" not in ir[:10]

    th = load_agent_prompt("threat-hunter")
    assert "MITRE ATT&CK" in th

    combined = build_triage_system_prompt()
    assert "action-proposal.v1" in combined
    assert "containment.block_ip" in combined

    with pytest.raises(ValueError):
        load_agent_prompt("../README")
    with pytest.raises(ValueError):
        load_agent_prompt("incident-responder.md")


def test_pii_phi_and_financial_redaction_preserves_network_telemetry():
    raw = (
        "Alert from 198.51.100.42 on 2026-11-24T01:00:00Z "
        "user=alice@example.com phone=555-867-5309 ssn=123-45-6789 "
        "MRN: HOSP-99281 diagnosis: J45.909 "
        "card=4111-1111-1111-1111 routing: 021000021"
    )
    redacted, counts = redact_sensitive_data(raw)

    # Network telemetry preserved
    assert "198.51.100.42" in redacted
    assert "2026-11-24T01:00:00Z" in redacted

    # Sensitive PII/PHI/Financial scrubbed
    assert "alice@example.com" not in redacted
    assert "555-867-5309" not in redacted
    assert "123-45-6789" not in redacted
    assert "HOSP-99281" not in redacted
    assert "J45.909" not in redacted
    assert "4111-1111-1111-1111" not in redacted
    assert "021000021" not in redacted

    assert counts["pii_email"] == 1
    assert counts["pii_phone"] == 1
    assert counts["pii_ssn"] == 1
    assert counts["phi_identifier"] == 1
    assert counts["phi_diagnosis"] == 1
    assert counts["financial_pan"] == 1
    assert counts["financial_account"] == 1


def test_parse_triage_proposals_valid_and_fail_closed():
    reply = (
        "VERDICT: malicious\n"
        "Observed SYN flood (T1498) targeting router.\n"
        "```json\n"
        '{"proposals": [{'
        '"action": "containment.block_ip", '
        '"action_class": "contain", '
        '"target": "203.0.113.77", '
        '"parameters": {"ip": "203.0.113.77", "ttl_seconds": 3600}, '
        '"rationale": "Active SYN flood disrupting WAN interface", '
        '"confidence": 0.94'
        "}]}\n"
        "```"
    )
    proposals = parse_triage_proposals(reply)
    assert len(proposals) == 1
    assert proposals[0]["action"] == "containment.block_ip"
    assert proposals[0]["target"] == "203.0.113.77"
    assert proposals[0]["confidence"] == 0.94

    # Unknown capability rejected
    bad_cap = '```json\n{"proposals": [{"action": "shell.exec", "action_class": "contain", "target": "1.2.3.4", "parameters": {}, "rationale": "x", "confidence": 0.9}]}\n```'
    assert parse_triage_proposals(bad_cap) == []

    # Non-finite confidence rejected
    bad_conf = '```json\n{"proposals": [{"action": "containment.block_ip", "action_class": "contain", "target": "1.2.3.4", "parameters": {}, "rationale": "x", "confidence": "NaN"}]}\n```'
    assert parse_triage_proposals(bad_conf) == []


def test_triage_threat_end_to_end_persists_timeline_and_redacts_input(tmp_path):
    db = Database(tmp_path / "triage.db")
    threat_id = db.insert_threat(
        ThreatEvent(
            timestamp=datetime.now(timezone.utc),
            router_name="edge-router",
            threat_type="ddos_syn_flood",
            source_ip="203.0.113.99",
            severity=Severity.CRITICAL,
            raw_log="SYN flood from 203.0.113.99 affecting user bob@example.com SSN 123-45-6789 MRN: PT-88421",
        )
    )

    model_reply = (
        "VERDICT: malicious\n"
        "Critical SYN flood (T1498.001) threatening router availability.\n"
        "```json\n"
        '{"proposals": [{'
        '"action": "containment.block_ip", '
        '"action_class": "contain", '
        '"target": "203.0.113.99", '
        '"parameters": {"ip": "203.0.113.99", "ttl_seconds": 3600}, '
        '"rationale": "Stop active SYN flood before hardware saturation", '
        '"confidence": 0.96'
        "}]}\n"
        "```"
    )
    fake_model = FakeModel(model_reply)
    handlers = DaemonCommandHandlers(db, None, analyze=fake_model)

    res = _run(handlers.triage_threat(_ctx({"threat_id": threat_id})))

    # Sensitive data never reached the analyst prompt
    assert len(fake_model.seen_prompts) == 1
    assert "bob@example.com" not in fake_model.seen_prompts[0]
    assert "123-45-6789" not in fake_model.seen_prompts[0]
    assert "PT-88421" not in fake_model.seen_prompts[0]
    assert "203.0.113.99" in fake_model.seen_prompts[0]

    # Structured WP5 response fields
    assert res["verdict"] == "malicious"
    assert res["disruptive_critical"] is True
    assert "T1498.001" in res["mitre_techniques"]
    assert len(res["proposals"]) == 1
    assert res["proposals"][0]["action"] == "containment.block_ip"
    assert res["triage_run_id"] >= 1
    assert res["redaction_summary"]["pii_email"] == 1
    assert res["redaction_summary"]["pii_ssn"] == 1
    assert res["redaction_summary"]["phi_identifier"] == 1

    # Timeline recommends auto provisional containment with timer for critical disruption
    proposal_steps = [s for s in res["triage_timeline"] if s["stage"] == "proposal"]
    assert len(proposal_steps) == 1
    assert proposal_steps[0]["recommended_gate"] == "auto_provisional_with_timer"

    # Persisted in SQLite and exportable as NIST SP 800-61 handoff profile
    stored = db.get_triage_run(res["triage_run_id"])
    assert stored is not None
    assert stored["threat_id"] == threat_id
    assert "123-45-6789" not in stored["redacted_event"]

    handoff_json = build_authority_handoff_profile(stored, output_format="json")
    assert isinstance(handoff_json, dict)
    assert handoff_json["schema_version"] == "aegissiem.handoff.v1"
    assert handoff_json["privacy_protection"]["pii_phi_financial_redacted"] is True
    assert len(handoff_json["chain_of_custody"]["evidence_sha256"]) == 64

    handoff_md = build_authority_handoff_profile(stored, output_format="markdown")
    assert isinstance(handoff_md, str)
    assert "Incident Forensic Handoff Profile" in handoff_md
    assert "T1498.001" in handoff_md
    assert "123-45-6789" not in handoff_md
    db.close()


def test_non_disruptive_threat_requires_operator_confirmation():
    assert classify_disruption("port scan detected", threat_type="port_scan", severity="HIGH", verdict="suspicious") is False
    assert classify_disruption("syn flood saturating WAN", threat_type="ddos", severity="CRITICAL", verdict="malicious") is True
    assert extract_mitre_techniques("Mapped T1110 and T1498.001 and T1110 again") == ["T1110", "T1498.001"]
