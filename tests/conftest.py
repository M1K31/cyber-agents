"""Shared fixtures for the daemon tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from daemon.ecosystem_bridge import _ensure_ecosystem_paths, reset_policy_singletons

HMAC_SECRET = "cyber-agents-phase3-test-secret-0123456789abcdef"


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
