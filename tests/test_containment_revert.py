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
