"""Shared UI assets: hermetic serving, clean absence, and erasure docs (CodeRabbit CA-T27, CA-T28, CA-T47)."""
from __future__ import annotations

import asyncio
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

from daemon import ecosystem_bridge
from daemon.aegissiem_daemon import create_api
from daemon.db import Database
from daemon.response import ResponsePipeline

REPO = Path(__file__).resolve().parent.parent


def _get(eco_env, paths):
    db = Database(str(eco_env / "aegissiem.db"))
    app = create_api(db, ResponsePipeline(db=db))

    async def go():
        out = {}
        async with TestClient(TestServer(app)) as client:
            for path in paths:
                resp = await client.get(path)
                out[path] = (resp.status, await resp.text())
        return out

    try:
        return asyncio.run(go())
    finally:
        db.close()


def test_ui_assets_are_served_from_the_ecosystem_root(eco_env, monkeypatch):
    # Provision stub assets instead of depending on a sibling appEcosystem
    # checkout having run `npm run build` (dist/ is not committed there).
    root = eco_env / "eco"
    (root / "theme").mkdir(parents=True)
    (root / "theme" / "ecosystem-theme.css").write_text(":root{--stub:1}")
    dist = root / "packages" / "ecosystem-ui-controls" / "dist"
    dist.mkdir(parents=True)
    (dist / "ecosystem-ui-controls.js").write_text("globalThis.EcosystemUIControls={};")
    monkeypatch.setattr(ecosystem_bridge, "_find_ecosystem_root", lambda: root)

    got = _get(eco_env, ["/ui/ecosystem-theme.css", "/ui/ecosystem-ui-controls.js"])

    assert got["/ui/ecosystem-theme.css"] == (200, ":root{--stub:1}")
    assert got["/ui/ecosystem-ui-controls.js"] == (200, "globalThis.EcosystemUIControls={};")


def test_dashboard_still_loads_and_explains_itself_when_assets_are_absent(eco_env, monkeypatch):
    monkeypatch.setattr(ecosystem_bridge, "resolve_ui_asset_path", lambda filename: None)

    got = _get(eco_env, ["/ui/ecosystem-ui-controls.js", "/ui/ecosystem-theme.css", "/dashboard/"])

    assert got["/ui/ecosystem-ui-controls.js"][0] == 404
    assert got["/ui/ecosystem-theme.css"][0] == 404
    status, html = got["/dashboard/"]
    assert status == 200
    # The page carries a notice the script reveals when the controls did not load,
    # rather than silently rendering without a policy bar or Freeze control.
    assert 'id="ui-assets-missing"' in html
    assert "Shared ecosystem UI controls are not installed" in html
    app_js = (REPO / "dashboard" / "app.js").read_text()
    assert "ui-assets-missing" in app_js
    assert "window.EcosystemUIControls" in app_js


def test_privacy_erasure_names_the_step_up_store():
    text = (REPO / "PRIVACY.md").read_text()
    erasure = text[text.index("## 5. Data Retention & Erasure"):text.index("## 6.")]
    assert "CYBER_HARNESS_STEP_UP_PATH" in erasure
    assert "step_up_credentials.json" in erasure
