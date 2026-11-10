"""Cleanup after a partial failure (CodeRabbit CA-T44, CA-T45)."""
from __future__ import annotations

import asyncio

import pytest

from daemon.db import Database
from daemon.honeypot import HoneypotManager
from daemon.response import ResponsePipeline


class FakeListener:
    service = "fake"

    def __init__(self, fail_times: int = 0):
        self.fail_times = fail_times
        self.stop_calls = 0
        self.stopped = False

    async def stop(self):
        self.stop_calls += 1
        if self.stop_calls <= self.fail_times:
            raise OSError("address still in use")
        self.stopped = True


def test_checkpoint_row_marked_failed_when_queue_rejects(eco_env, monkeypatch):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        pipeline = ResponsePipeline(db=db)

        def reject(*args, **kwargs):
            raise RuntimeError("queue full")

        monkeypatch.setattr(pipeline.approval_manager.approval_queue, "request_approval", reject)

        with pytest.raises(RuntimeError, match="queue full"):
            pipeline.approval_manager.create_checkpoint(profile_id=0, action="x", summary="s")

        # No orphan an operator could later "approve" for an action that was
        # never queued (and, for a honeypot, has already been torn down).
        assert db.get_pending_approvals() == []
        rows = db.conn.execute("SELECT status FROM approvals").fetchall()
        assert [r["status"] for r in rows] == ["failed"]
    finally:
        db.close()


def test_stop_all_attempts_every_listener_and_keeps_failures(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        mgr = HoneypotManager(db)
        a, b, c = FakeListener(), FakeListener(fail_times=1), FakeListener()
        mgr._listeners = [a, b, c]

        assert asyncio.run(mgr.stop_all()) == 1

        assert a.stopped and c.stopped
        assert mgr._listeners == [b]  # still ours to stop

        assert asyncio.run(mgr.stop_all()) == 0  # the retry succeeds
        assert b.stopped
        assert mgr._listeners == []
    finally:
        db.close()


def test_failed_honeypot_teardown_keeps_the_lease_and_is_retried(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        mgr = HoneypotManager(db)
        stuck = FakeListener(fail_times=1)
        mgr._listeners = [FakeListener(), stuck]
        pipeline = ResponsePipeline(db=db, honeypot_manager=mgr)
        pipeline._active_honeypot_lease = 7

        assert asyncio.run(pipeline._teardown_honeypot(7)) is False
        assert pipeline._active_honeypot_lease == 7
        assert pipeline._honeypot_teardown_pending == 7

        asyncio.run(pipeline._retry_pending_honeypot_teardown())
        assert stuck.stopped
        assert pipeline._active_honeypot_lease is None
        assert pipeline._honeypot_teardown_pending is None
    finally:
        db.close()


def test_teardown_for_a_superseded_lease_does_not_stop_the_newer_deployment(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        mgr = HoneypotManager(db)
        live = FakeListener()
        mgr._listeners = [live]
        pipeline = ResponsePipeline(db=db, honeypot_manager=mgr)
        pipeline._active_honeypot_lease = 8
        pipeline._honeypot_teardown_pending = 7  # an old failed teardown

        assert asyncio.run(pipeline._teardown_honeypot(7)) is True
        asyncio.run(pipeline._retry_pending_honeypot_teardown())

        assert live.stop_calls == 0
        assert pipeline._active_honeypot_lease == 8
        assert pipeline._honeypot_teardown_pending is None
    finally:
        db.close()
