"""Unblock is reported and recorded only after the router confirms (CodeRabbit CA-T22, CA-T30)."""
from __future__ import annotations

import asyncio
import os

from aiohttp.test_utils import TestClient, TestServer

from daemon import router_ssh
from daemon.aegissiem_daemon import create_api
from daemon.db import Database
from daemon.models import BlockedIP
from daemon.response import ResponsePipeline


def _fake_run(output: str, ok: bool = True, calls: list | None = None):
    async def run(host, command, username="admin", key_file=None, port=22, retries=1):
        if calls is not None:
            calls.append(command)
        return ok, output

    return run


def test_router_unblock_false_when_rule_still_present(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(router_ssh, "_run_command", _fake_run("PRESENT", calls=calls))
    assert asyncio.run(router_ssh.unblock_ip("198.51.100.42", "r", "u", "k")) is False
    assert len(calls) == 2
    assert all("while iptables -D" in c and "iptables -C" in c for c in calls)
    assert "INPUT" in calls[0] and "FORWARD" in calls[1]


def test_router_unblock_false_on_transport_failure(monkeypatch):
    monkeypatch.setattr(router_ssh, "_run_command", _fake_run("Max retries exceeded", ok=False))
    assert asyncio.run(router_ssh.unblock_ip("198.51.100.42", "r", "u", "k")) is False


def test_router_unblock_false_when_check_is_inconclusive(monkeypatch):
    # e.g. xtables lock held, or an iptables too old for -C: not proof of removal.
    monkeypatch.setattr(router_ssh, "_run_command", _fake_run("UNKNOWN"))
    assert asyncio.run(router_ssh.unblock_ip("198.51.100.42", "r", "u", "k")) is False


def test_router_unblock_true_when_both_chains_absent(monkeypatch):
    monkeypatch.setattr(router_ssh, "_run_command", _fake_run("some warning\nABSENT\n"))
    assert asyncio.run(router_ssh.unblock_ip("198.51.100.42", "r", "u", "k")) is True


def test_router_unblock_true_requires_both_chains(monkeypatch):
    outputs = iter(["ABSENT", "PRESENT"])

    async def run(host, command, username="admin", key_file=None, port=22, retries=1):
        return True, next(outputs)

    monkeypatch.setattr(router_ssh, "_run_command", run)
    assert asyncio.run(router_ssh.unblock_ip("198.51.100.42", "r", "u", "k")) is False


def test_router_unblock_uses_ip6tables_for_ipv6(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(router_ssh, "_run_command", _fake_run("ABSENT", calls=calls))
    assert asyncio.run(router_ssh.unblock_ip("2001:db8::1", "r", "u", "k")) is True
    assert all("ip6tables -D" in c and "ip6tables -C" in c for c in calls)


def _api(eco_env, monkeypatch, router_result, seen: list):
    from ecosystem_auth.tokens import sign_request

    async def fake_router_unblock(ip, host, username="admin", key_file=None, port=22):
        seen.append(ip)
        return router_result

    monkeypatch.setattr("daemon.response.unblock_ip", fake_router_unblock)
    db = Database(str(eco_env / "aegissiem.db"))
    pipeline = ResponsePipeline(db=db, router_host="192.0.2.1")
    app = create_api(db, pipeline)

    async def post_unblock(segment: str):
        path = f"/api/blocked/{segment}/unblock"
        body = {"reason": "test"}
        headers = sign_request("POST", path, os.environ["ECOSYSTEM_HMAC_SECRET"], body=body)
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(path, json=body, headers=headers)
            return resp.status, await resp.json()

    return db, post_unblock


def test_api_unblock_failure_keeps_ip_blocked(eco_env, monkeypatch):
    seen: list[str] = []
    db, post_unblock = _api(eco_env, monkeypatch, False, seen)
    try:
        db.insert_blocked_ip(BlockedIP(ip="198.51.100.42", router_name="edge-router"))

        status, payload = asyncio.run(post_unblock("198.51.100.42"))

        assert status == 502
        assert payload["status"] == "error"
        assert payload["ip"] == "198.51.100.42"
        assert seen == ["198.51.100.42"]
        assert any(b.ip == "198.51.100.42" for b in db.get_blocked_ips(active_only=True))
    finally:
        db.close()


def test_api_unblock_success_clears_row_stored_in_non_canonical_form(eco_env, monkeypatch):
    seen: list[str] = []
    db, post_unblock = _api(eco_env, monkeypatch, True, seen)
    try:
        stored = "2001:0db8:0000:0000:0000:0000:0000:0001"
        row_id = db.insert_blocked_ip(BlockedIP(ip=stored, router_name="edge-router"))

        status, payload = asyncio.run(post_unblock(str(row_id)))

        assert status == 200
        assert payload == {"status": "unblocked", "ip": "2001:db8::1"}
        # Router gets the validated canonical address; the DB row is matched by
        # the string it was stored under.
        assert seen == ["2001:db8::1"]
        assert db.get_blocked_ips(active_only=True) == []
    finally:
        db.close()


def test_pipeline_unblock_without_router_updates_db(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    try:
        db.insert_blocked_ip(BlockedIP(ip="198.51.100.42", router_name="unmanaged"))
        pipeline = ResponsePipeline(db=db)
        assert asyncio.run(pipeline.unblock("198.51.100.42")) is True
        assert db.get_blocked_ips(active_only=True) == []
    finally:
        db.close()
