"""Unit tests for cyber-agents Phase 2 HubRuntime, capabilities, and safe iMessage argv delivery."""
from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest

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



def _threat_event():
    from daemon.models import Severity, ThreatEvent, ThreatStatus

    return ThreatEvent(
        timestamp=datetime(2026, 11, 1, 20, 15, 0),
        router_name="edge-gw",
        threat_type="ssh_bruteforce",
        source_ip="203.0.113.42",
        severity=Severity.HIGH,
        raw_log="x",
        status=ThreatStatus.open,
    )


def test_scheduled_hub_publish_is_not_reported_as_delivered(monkeypatch):
    from daemon import ecosystem_bridge

    monkeypatch.setattr(
        ecosystem_bridge,
        "publish_threat_notification_sync",
        lambda *a, **k: {"status": "scheduled", "dedupe_key": "k"},
    )
    channels = notifications.notify(_threat_event())
    assert "ecosystem" not in channels
    assert "ecosystem:scheduled" in channels


def test_completed_hub_publish_is_reported_as_delivered(monkeypatch):
    from daemon import ecosystem_bridge

    monkeypatch.setattr(
        ecosystem_bridge,
        "publish_threat_notification_sync",
        lambda *a, **k: {"status": "queued_offline"},
    )
    assert notifications.notify(_threat_event()) == ["ecosystem"]


def test_scheduled_publish_task_is_retained_and_its_failure_is_logged(caplog):
    from daemon import ecosystem_bridge

    class DownHub:
        async def notify(self, *args, **kwargs):
            raise RuntimeError("hub down")

    async def _run():
        out = ecosystem_bridge.publish_threat_notification_sync(_threat_event(), hub=DownHub())
        assert out["status"] == "scheduled"
        # Held by the module so the loop's weak reference cannot let it be
        # collected mid-flight.
        assert len(ecosystem_bridge._pending_publish_tasks) == 1
        for _ in range(5):
            await asyncio.sleep(0)
        assert len(ecosystem_bridge._pending_publish_tasks) == 0

    with caplog.at_level("WARNING"):
        asyncio.run(_run())
    failures = [r for r in caplog.records if "scheduled hub publish" in r.getMessage().lower()]
    assert len(failures) == 1
    assert "203.0.113.42:high" in failures[0].getMessage()  # dedupe key, no payload


@pytest.mark.parametrize(
    "timestamp",
    [
        datetime(2026, 11, 1, 20, 15, 0),
        "2026-11-01T20:15:00",
        "2026-11-01 20:15:00",
        "2026-11-01T20:15:00.123456",
        "2026-11-01T20:59:59Z",
    ],
)
def test_dedupe_key_is_the_same_for_datetime_and_iso_string(timestamp):
    """Kept identical to AegisSIEM's key: one instant must give one key in both apps."""
    threat = SimpleNamespace(threat_type="ssh_bruteforce", source_ip="203.0.113.42", timestamp=timestamp)
    assert threat_dedupe_key(threat) == "aegissiem:ssh_bruteforce:203.0.113.42:medium:2026110120"


def test_dedupe_key_tolerates_an_unparseable_timestamp():
    threat = SimpleNamespace(threat_type="x", source_ip="1.2.3.4", timestamp="yesterday-ish")
    assert threat_dedupe_key(threat).startswith("aegissiem:x:1.2.3.4:medium:")
