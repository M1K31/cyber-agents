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


class _HeldServer:
    """A server whose wait_closed() never returns while a client is connected."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        await asyncio.Event().wait()


def test_listener_stop_drops_a_client_that_holds_the_connection(eco_env, monkeypatch):
    # Since Python 3.12 Server.wait_closed() waits for every open connection. A
    # tarpitted attacker who never hangs up must not be able to block teardown
    # (and, through the auto-block loop's retry, the whole containment loop) —
    # and "stopped" must mean their connection is actually gone.
    from daemon import honeypot

    monkeypatch.setattr(honeypot, "STOP_WAIT_SECONDS", 0.05)
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        listener = honeypot.BaseListener(db, port=2222)
        server = _HeldServer()
        listener._server = server
        state = {}

        class Writer:
            closed = False

            def get_extra_info(self, name):
                return ("203.0.113.5", 4444)

            def close(self):
                Writer.closed = True

            async def wait_closed(self):
                return None

        async def tarpit(reader, writer, attacker_ip):
            await asyncio.Event().wait()  # holds the connection forever

        listener._interact = tarpit

        async def scenario():
            client = asyncio.ensure_future(listener._handle_connection(None, Writer()))
            await asyncio.sleep(0)
            assert len(listener._client_tasks) == 1
            await asyncio.wait_for(listener.stop(), timeout=2)
            state["client_done"] = client.done()

        asyncio.run(scenario())

        assert server.closed            # no new connections
        assert state["client_done"]     # the held one was dropped
        assert Writer.closed
        assert listener._client_tasks == set()
        assert listener._server is None
    finally:
        db.close()


def test_listener_stop_reports_failure_if_a_connection_cannot_be_dropped(eco_env, monkeypatch):
    from daemon import honeypot

    monkeypatch.setattr(honeypot, "STOP_WAIT_SECONDS", 0.05)
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        mgr = HoneypotManager(db)
        listener = honeypot.BaseListener(db, port=2222)
        listener._server = _HeldServer()
        mgr._listeners = [listener]

        async def scenario():
            release = asyncio.Event()

            async def refuses_to_die():
                while not release.is_set():
                    try:
                        await release.wait()
                    except asyncio.CancelledError:
                        continue  # ignores cancellation

            stubborn = asyncio.ensure_future(refuses_to_die())
            try:
                listener._client_tasks.add(stubborn)
                await asyncio.sleep(0)
                # Still running => still this manager's to stop, teardown stays pending.
                assert await asyncio.wait_for(mgr.stop_all(), timeout=2) == 1
                assert mgr._listeners == [listener]
                assert listener._server is not None
            finally:
                release.set()
                await stubborn

        asyncio.run(scenario())
    finally:
        db.close()


def test_teardown_does_not_clobber_a_lease_claimed_while_it_was_stopping(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        mgr = HoneypotManager(db)
        pipeline = ResponsePipeline(db=db, honeypot_manager=mgr)

        class ClaimsNewLeaseWhileStopping(FakeListener):
            async def stop(self):
                await super().stop()
                pipeline._active_honeypot_lease = 9  # a newer deployment took over

        mgr._listeners = [ClaimsNewLeaseWhileStopping()]
        pipeline._active_honeypot_lease = 7

        assert asyncio.run(pipeline._teardown_honeypot(7)) is True
        assert pipeline._active_honeypot_lease == 9
    finally:
        db.close()


def test_failed_teardown_records_the_lease_it_was_asked_to_tear_down(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        mgr = HoneypotManager(db)
        pipeline = ResponsePipeline(db=db, honeypot_manager=mgr)

        class FailsAndLeaseMoves(FakeListener):
            async def stop(self):
                pipeline._active_honeypot_lease = 9
                raise OSError("busy")

        mgr._listeners = [FailsAndLeaseMoves()]
        pipeline._active_honeypot_lease = 7

        assert asyncio.run(pipeline._teardown_honeypot(7)) is False
        assert pipeline._honeypot_teardown_pending == 7
        assert pipeline._active_honeypot_lease == 9
    finally:
        db.close()
