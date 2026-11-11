"""A denied or expired provisional block must stay unblocked (CodeRabbit CA-T03)."""
from __future__ import annotations

from datetime import datetime, timedelta

from daemon.db import Database
from daemon.models import BlockedIP, Severity, ThreatEvent, ThreatStatus
from daemon.response import ResponsePipeline


def _overdue_blocked_threat(db: Database, ip: str) -> int:
    threat_id = db.insert_threat(
        ThreatEvent(
            timestamp=datetime.utcnow(),
            router_name="edge-router",
            threat_type="ssh_brute_force",
            source_ip=ip,
            severity=Severity.HIGH,
            raw_log=f"Failed password for root from {ip}",
            status=ThreatStatus.open,
            auto_block_at=datetime.utcnow() - timedelta(minutes=5),
        )
    )
    db.insert_blocked_ip(BlockedIP(ip=ip, router_name="edge-router"))
    db.update_threat_status(threat_id, ThreatStatus.blocked)
    return threat_id


def test_denied_provisional_block_leaves_no_auto_block_deadline(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        pipeline = ResponsePipeline(db=db)
        threat_id = _overdue_blocked_threat(db, "198.51.100.42")

        pipeline._revert_provisional_containment(
            {"revert_plan": {"unblock_ip": "198.51.100.42", "threat_id": threat_id}}
        )

        threat = db.get_threat(threat_id)
        assert threat.status == ThreatStatus.open
        assert threat.auto_block_at is None
        # The auto-block loop selects from exactly this query; the denied
        # threat must not be eligible, or it is re-blocked within a minute.
        assert db.get_open_threats_past_deadline() == []
        assert db.get_blocked_ips() == []
    finally:
        db.close()


def test_clearing_one_deadline_leaves_other_overdue_threats_eligible(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        denied = _overdue_blocked_threat(db, "198.51.100.42")
        other = db.insert_threat(
            ThreatEvent(
                timestamp=datetime.utcnow(),
                router_name="edge-router",
                threat_type="port_scan",
                source_ip="203.0.113.9",
                severity=Severity.HIGH,
                raw_log="scan",
                status=ThreatStatus.open,
                auto_block_at=datetime.utcnow() - timedelta(minutes=1),
            )
        )

        db.clear_auto_block_deadline(denied)

        assert [t.id for t in db.get_open_threats_past_deadline()] == [other]
    finally:
        db.close()


# ── The denial / TTL-expiry path must be as truthful as the Unblock button ──

import asyncio  # noqa: E402


def _blocked(db: Database, ip: str) -> int:
    return _overdue_blocked_threat(db, ip)


def test_revert_waits_for_the_router_before_recording_the_unblock(eco_env, monkeypatch):
    calls: list[str] = []

    async def router_ok(ip, host, username="admin", key_file=None, port=22):
        calls.append(ip)
        return True

    monkeypatch.setattr("daemon.response.unblock_ip", router_ok)
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        pipeline = ResponsePipeline(db=db, router_host="192.0.2.1")
        threat_id = _blocked(db, "198.51.100.42")

        async def scenario():
            pipeline._revert_provisional_containment(
                {"revert_plan": {"unblock_ip": "198.51.100.42", "threat_id": threat_id}}
            )
            # Nothing is recorded until the router has answered.
            assert [b.ip for b in db.get_blocked_ips()] == ["198.51.100.42"]
            await asyncio.gather(*pipeline._background_tasks)

        asyncio.run(scenario())

        assert calls == ["198.51.100.42"]
        assert db.get_blocked_ips() == []
        assert db.get_threat(threat_id).status == ThreatStatus.open
        assert db.get_threat(threat_id).auto_block_at is None
    finally:
        db.close()


def test_revert_keeps_the_ip_blocked_when_the_router_does_not_confirm_then_retries(eco_env, monkeypatch):
    router = {"up": False}

    async def router_unblock(ip, host, username="admin", key_file=None, port=22):
        return router["up"]

    monkeypatch.setattr("daemon.response.unblock_ip", router_unblock)
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        pipeline = ResponsePipeline(db=db, router_host="192.0.2.1")
        threat_id = _blocked(db, "198.51.100.42")

        async def denied_while_router_down():
            pipeline._revert_provisional_containment(
                {"revert_plan": {"unblock_ip": "198.51.100.42", "threat_id": threat_id}}
            )
            await asyncio.gather(*pipeline._background_tasks)

        asyncio.run(denied_while_router_down())

        # The router is still dropping this IP, so it must still be listed as
        # blocked and the threat must not be reported as reopened.
        assert [b.ip for b in db.get_blocked_ips()] == ["198.51.100.42"]
        assert db.get_threat(threat_id).status == ThreatStatus.blocked
        # …but the denial is not forgotten, and is not re-blocked meanwhile.
        assert db.get_threat(threat_id).auto_block_at is None
        assert pipeline._pending_reverts == {"198.51.100.42": threat_id}

        router["up"] = True
        asyncio.run(pipeline._retry_pending_reverts())

        assert db.get_blocked_ips() == []
        assert db.get_threat(threat_id).status == ThreatStatus.open
        assert pipeline._pending_reverts == {}
    finally:
        db.close()


def test_revert_without_a_running_loop_is_queued_not_recorded(eco_env, monkeypatch):
    async def router_ok(ip, host, username="admin", key_file=None, port=22):
        return True

    monkeypatch.setattr("daemon.response.unblock_ip", router_ok)
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        pipeline = ResponsePipeline(db=db, router_host="192.0.2.1")
        threat_id = _blocked(db, "198.51.100.42")

        pipeline._revert_provisional_containment(  # called from sync code
            {"revert_plan": {"unblock_ip": "198.51.100.42", "threat_id": threat_id}}
        )

        assert [b.ip for b in db.get_blocked_ips()] == ["198.51.100.42"]
        assert pipeline._pending_reverts == {"198.51.100.42": threat_id}
        asyncio.run(pipeline._retry_pending_reverts())
        assert db.get_blocked_ips() == []
    finally:
        db.close()


def test_a_queued_revert_never_removes_a_newer_block_of_the_same_ip(eco_env, monkeypatch):
    unblocked: list[str] = []

    async def router_unblock(ip, host, username="admin", key_file=None, port=22):
        unblocked.append(ip)
        return True

    async def router_block(ip, host, username="admin", key_file=None, port=22):
        return True

    monkeypatch.setattr("daemon.response.unblock_ip", router_unblock)
    monkeypatch.setattr("daemon.response.block_ip", router_block)
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        pipeline = ResponsePipeline(db=db, router_host="192.0.2.1")
        old = _blocked(db, "198.51.100.42")
        # A denial of the old block is still waiting for the router…
        pipeline._pending_reverts["198.51.100.42"] = old
        # …when the same address is legitimately blocked again.
        new = db.insert_threat(
            ThreatEvent(
                timestamp=datetime.utcnow(), router_name="edge-router", threat_type="port_scan",
                source_ip="198.51.100.42", severity=Severity.HIGH, raw_log="scan", status=ThreatStatus.open,
            )
        )

        async def scenario():
            assert await pipeline.block_threat(new) == "blocked"
            await pipeline._retry_pending_reverts()

        asyncio.run(scenario())

        assert pipeline._pending_reverts == {}
        assert unblocked == []
        assert any(b.ip == "198.51.100.42" for b in db.get_blocked_ips())
        assert db.get_threat(new).status == ThreatStatus.blocked
    finally:
        db.close()


def test_denying_an_older_block_does_not_lift_a_newer_block_of_the_same_ip(eco_env, monkeypatch):
    unblocked: list[str] = []

    async def router_unblock(ip, host, username="admin", key_file=None, port=22):
        unblocked.append(ip)
        return True

    async def router_block(ip, host, username="admin", key_file=None, port=22):
        return True

    monkeypatch.setattr("daemon.response.unblock_ip", router_unblock)
    monkeypatch.setattr("daemon.response.block_ip", router_block)
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        pipeline = ResponsePipeline(db=db, router_host="192.0.2.1")

        def threat(kind):
            return db.insert_threat(
                ThreatEvent(
                    timestamp=datetime.utcnow(), router_name="edge-router", threat_type=kind,
                    source_ip="198.51.100.42", severity=Severity.HIGH, raw_log=kind, status=ThreatStatus.open,
                )
            )

        older, newer = threat("ssh_brute_force"), threat("port_scan")

        async def scenario():
            assert await pipeline.block_threat(older) == "blocked"
            assert await pipeline.block_threat(newer) == "blocked"
            # The OLDER block's provisional checkpoint is now denied (or expires).
            pipeline._revert_provisional_containment(
                {"revert_plan": {"unblock_ip": "198.51.100.42", "threat_id": older}}
            )
            await asyncio.gather(*pipeline._background_tasks)
            await pipeline._retry_pending_reverts()

        asyncio.run(scenario())

        assert unblocked == []
        assert pipeline._pending_reverts == {}
        assert any(b.ip == "198.51.100.42" for b in db.get_blocked_ips())
        assert db.get_threat(newer).status == ThreatStatus.blocked
    finally:
        db.close()
