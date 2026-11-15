"""Shared fixtures for the daemon tests, and a suite-wide network guard.

Network guard: the daemon reaches the hub (registry, AI profile, approval
checks) and model providers over HTTP. Every real httpx/urllib transport is
refused during tests, so a run never talks to live services on the machine and
passes or fails the same everywhere. In-process transports (httpx.MockTransport,
aiohttp's TestClient) are unaffected. A test that genuinely needs real sockets
opts out with @pytest.mark.allow_network.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

import httpx
import pytest

from daemon.ecosystem_bridge import _ensure_ecosystem_paths, reset_policy_singletons

HMAC_SECRET = "cyber-agents-phase3-test-secret-0123456789abcdef"
_GUARD_MESSAGE = "blocked by the test-suite network guard (use @pytest.mark.allow_network to opt out)"


def pytest_configure(config):
    config.addinivalue_line("markers", "allow_network: let this test open real HTTP connections")


@pytest.fixture(autouse=True)
def _no_real_http(request, monkeypatch):
    if request.node.get_closest_marker("allow_network"):
        return

    def _blocked_sync(self, req):
        raise httpx.ConnectError(f"{req.url}: {_GUARD_MESSAGE}", request=req)

    async def _blocked_async(self, req):
        raise httpx.ConnectError(f"{req.url}: {_GUARD_MESSAGE}", request=req)

    def _blocked_urlopen(url, *args, **kwargs):
        target = getattr(url, "full_url", url)
        raise urllib.error.URLError(f"{target}: {_GUARD_MESSAGE}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _blocked_sync)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _blocked_async)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked_urlopen)


@pytest.fixture
def eco_env(tmp_path: Path, monkeypatch) -> Path:
    """Isolated state dir, step-up store and HMAC secret; fresh policy singletons.

    Returns ``tmp_path`` so a test can place its database beside the state.
    """
    monkeypatch.setenv("CYBER_HARNESS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CYBER_HARNESS_STEP_UP_PATH", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", HMAC_SECRET)
    reset_policy_singletons()
    _ensure_ecosystem_paths()
    yield tmp_path
    reset_policy_singletons()
