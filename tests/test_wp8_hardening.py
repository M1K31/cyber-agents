"""WP8 hardening & operability tests for cyber-agents."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from daemon import router_ssh
from daemon.aegissiem_daemon import create_api
from daemon.db import Database
from daemon.response import ResponsePipeline


def test_unsigned_loopback_freeze_event_is_rejected(eco_env):
    """WP8: unauthenticated loopback callers must NOT be able to freeze the daemon."""
    db = Database(str(eco_env / "aegissiem.db"))
    pipeline = ResponsePipeline(db=db)
    app = create_api(db, pipeline)

    async def go():
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/ecosystem/events",
                json={"type": "policy.freeze", "data": {"initiated_by": "rogue-test"}},
            )
            return resp.status

    status = asyncio.run(go())
    assert status == 401
    assert pipeline.policy_engine.export_state()["frozen"] is False


def test_router_ssh_fails_closed_without_known_hosts(tmp_path: Path, monkeypatch):
    """WP8: router SSH must fail closed when no pinned known_hosts file exists."""
    missing = tmp_path / "does_not_exist_known_hosts"
    monkeypatch.setenv("ROUTER_SSH_KNOWN_HOSTS", str(missing))

    with pytest.raises(PermissionError, match="known_hosts"):
        asyncio.run(router_ssh._ssh_connect("192.168.1.1"))


def test_router_ssh_passes_pinned_known_hosts_and_connect_timeout(tmp_path: Path, monkeypatch):
    """WP8: router SSH passes pinned known_hosts path and explicit connect_timeout."""
    kh = tmp_path / "known_hosts"
    kh.write_text("192.168.1.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n", encoding="utf-8")

    captured: dict = {}

    async def _fake_connect(**kwargs):
        captured.update(kwargs)
        return "fake-conn"

    monkeypatch.setattr(router_ssh.asyncssh, "connect", _fake_connect)
    conn = asyncio.run(
        router_ssh._ssh_connect(
            "192.168.1.1",
            username="admin",
            port=2222,
            connect_timeout=7.5,
            known_hosts_path=str(kh),
        )
    )
    assert conn == "fake-conn"
    assert captured["known_hosts"] == str(kh)
    assert captured["connect_timeout"] == 7.5
    assert captured["login_timeout"] == 7.5
    assert captured["port"] == 2222
