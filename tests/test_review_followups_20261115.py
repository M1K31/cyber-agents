"""Pins for CodeRabbit PR #1 findings that were fixed without a test (2026-11-15)."""
from __future__ import annotations

import asyncio

import pytest
from aiohttp.test_utils import TestClient, TestServer

from daemon import ecosystem_bridge
from daemon.aegissiem_daemon import create_api
from daemon.db import Database
from daemon.response import ResponsePipeline


@pytest.mark.parametrize("name", ["../../etc/passwd", "..", "a/b.woff2", "..\\x", ""])
def test_font_names_cannot_leave_the_font_directory(name):
    assert ecosystem_bridge.resolve_ui_asset_path(f"fonts/{name}") is None


def test_hub_freeze_event_freezes_the_pipeline(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    pipeline = ResponsePipeline(db=db)
    app = create_api(db, pipeline)

    async def go():
        async with TestClient(TestServer(app)) as client:
            # TestClient connects from loopback, which the route accepts like a signed peer.
            resp = await client.post("/ecosystem/events", json={"type": "policy.freeze",
                                                                "data": {"initiated_by": "hub"}})
            return resp.status, await resp.json()

    status, body = asyncio.run(go())
    assert status == 200 and body["status"] == "frozen"
    assert pipeline.policy_engine.export_state()["frozen"] is True


def test_a_cross_site_freeze_event_is_rejected(eco_env):
    db = Database(str(eco_env / "aegissiem.db"))
    pipeline = ResponsePipeline(db=db)
    app = create_api(db, pipeline)

    async def go():
        async with TestClient(TestServer(app)) as client:
            resp = await client.post("/ecosystem/events", json={"type": "policy.freeze"},
                                     headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
            return resp.status

    assert asyncio.run(go()) == 403
    assert pipeline.policy_engine.export_state()["frozen"] is False
