"""Unit tests for cyber-agents Phase 2 HubRuntime, capabilities, and safe iMessage argv delivery."""
from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace

from daemon.ecosystem_bridge import (
    _ensure_ecosystem_paths,
    build_cyber_agents_capabilities,
    publish_threat_notification,
    start_daemon_hub,
    stop_daemon_hub,
    threat_dedupe_key,
)
from daemon import notifications


def test_cyber_agents_capabilities_validate_against_schema():
    _ensure_ecosystem_paths()
    from ecosystem_client.contracts import assert_valid_schema

    caps = build_cyber_agents_capabilities()
    names = {c["capability"] for c in caps}
    assert {"security.triage_threat", "security.honeypot_status"} <= names
    for partial in caps:
        full = dict(partial)
        full.setdefault("schema_version", 1)
        full.setdefault("provider", {"app": "aegissiem_daemon", "device_id": "test-daemon-01"})
        assert_valid_schema(full, "capability-manifest.v1")


def test_send_imessage_uses_argv_without_applescript_interpolation(monkeypatch):
    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(notifications.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(notifications.subprocess, "run", _fake_run)

    malicious_msg = 'Alert" & do shell script "id" & "'
    malicious_rcpt = 'user@example.com" & quit & "'
    ok = notifications.send_imessage(malicious_rcpt, malicious_msg)
    assert ok is True
    cmd = captured["cmd"]
    assert cmd[0] == "osascript"
    assert cmd[1] == "-e"
    assert "on run argv" in cmd[2]
    assert "do shell script" not in cmd[2]
    assert cmd[3] == malicious_rcpt
    assert cmd[4] == malicious_msg


def test_daemon_hub_offline_deduplication(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_HUB_ROLE", "off")
    _ensure_ecosystem_paths()
    from ecosystem_hub import HubRuntime

    threat = SimpleNamespace(
        threat_type="ssh_bruteforce",
        source_ip="203.0.113.42",
        router_name="edge-gw",
        severity=SimpleNamespace(value="high"),
        timestamp=datetime(2026, 11, 1, 20, 15, 0),
    )
    # Dedupe key now includes severity so an escalation is not suppressed.
    assert threat_dedupe_key(threat) == "aegissiem:ssh_bruteforce:203.0.113.42:high:2026110120"

    async def _run():
        hub = HubRuntime(
            app_name="aegissiem_daemon",
            service_port=8088,
            priority=15,
            role="off",
            outbox_path=tmp_path / "outbox.db",
            lock_path=tmp_path / "hub.lock",
            capabilities=build_cyber_agents_capabilities(),
        )
        await hub.start()
        r1 = await publish_threat_notification(threat, hub=hub)
        r2 = await publish_threat_notification(threat, hub=hub)
        assert r1["status"] == "queued_offline"
        assert r2["status"] == "deduplicated_offline"
        assert hub.outbox.pending_count() == 1
        await hub.stop()

        await start_daemon_hub(8088)
        await stop_daemon_hub()

    asyncio.run(_run())

