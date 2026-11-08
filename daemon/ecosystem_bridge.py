"""Phase 2 & 3 HubRuntime, capability manifest, policy/approval singletons, and deduplicated notification bridge for cyber-agents (priority=15)."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

_active_hub: Any = None
_policy_engine: Any = None
_step_up_auth: Any = None
_approval_queue: Any = None


def _find_ecosystem_root() -> Path | None:
    env = os.environ.get("APP_ECOSYSTEM_PATH")
    candidates = [Path(env).expanduser()] if env else []
    for parent in Path(__file__).resolve().parents:
        candidates.append(parent / "appEcosystem")
    for root in candidates:
        if root.is_dir():
            return root.resolve()
    return None


def _ensure_ecosystem_paths() -> None:
    root = _find_ecosystem_root()
    if root is not None:
        for rel in (
            "",
            "auth/python",
            "packages/ecosystem-client",
            "packages/ecosystem-ai",
            "packages/ecosystem-hub",
            "packages/ecosystem-policy",
        ):
            p = (root / rel).resolve()
            if p.is_dir() and str(p) not in sys.path:
                sys.path.insert(0, str(p))


def _state_dir() -> Path:
    d = Path(os.environ.get("CYBER_HARNESS_STATE_DIR") or (Path.home() / ".aegissiem-daemon"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_policy_engine() -> Any:
    """Return process-wide blue-team `PolicyEngine` persisted in `CYBER_HARNESS_STATE_DIR`."""
    global _policy_engine
    if _policy_engine is None:
        _ensure_ecosystem_paths()
        from ecosystem_policy import PolicyEngine

        _policy_engine = PolicyEngine(
            authority="standalone_local",
            persistence_path=_state_dir() / "policy_state.json",
        )
    return _policy_engine


def get_step_up_auth() -> Any:
    """Return process-wide `StepUpAuthenticator` for TOTP / Passkey / Device-Key step-up verification."""
    global _step_up_auth
    if _step_up_auth is None:
        _ensure_ecosystem_paths()
        from ecosystem_policy import StepUpAuthenticator

        store_env = os.environ.get("CYBER_HARNESS_STEP_UP_PATH")
        store_path = Path(store_env) if store_env else None
        _step_up_auth = StepUpAuthenticator(store_path=store_path)
    return _step_up_auth


def get_approval_queue(revert_callback: Callable[[dict[str, Any]], Any] | None = None) -> Any:
    """Return process-wide `LocalApprovalQueue` (`F10` unified approval store)."""
    global _approval_queue
    if _approval_queue is None:
        _ensure_ecosystem_paths()
        from ecosystem_policy import LocalApprovalQueue

        _approval_queue = LocalApprovalQueue(
            db_path=_state_dir() / "unified_approvals.db",
            step_up=get_step_up_auth(),
            revert_callback=revert_callback,
        )
    elif revert_callback is not None and getattr(_approval_queue, "_revert_cb", None) is None:
        _approval_queue._revert_cb = revert_callback
    return _approval_queue


def reset_policy_singletons() -> None:
    """Reset cached policy/step-up/approval singletons (used by isolated unit tests)."""
    global _policy_engine, _step_up_auth, _approval_queue
    _policy_engine = None
    _step_up_auth = None
    _approval_queue = None


def resolve_ui_asset_path(filename: str) -> Path | None:
    """Resolve shared `@appecosystem/ui-controls` bundle or Apple HIG theme CSS."""
    # Fonts are the only variable-named assets; confine them to a flat basename so
    # an encoded-traversal request (fonts/../../etc/passwd) cannot escape the theme
    # directory. The .js/.css names are matched exactly below and need no guard.
    if filename.startswith("fonts/"):
        font_name = filename[len("fonts/"):]
        if not font_name or "/" in font_name or "\\" in font_name or ".." in font_name:
            return None
    root = _find_ecosystem_root()
    candidates: list[Path] = []
    if root is not None:
        if filename == "ecosystem-ui-controls.js":
            candidates.append(root / "packages" / "ecosystem-ui-controls" / "dist" / "ecosystem-ui-controls.js")
        elif filename == "ecosystem-theme.css":
            candidates.append(root / "theme" / "ecosystem-theme.css")
        elif filename.startswith("fonts/"):
            candidates.append(root / "theme" / filename)
    local_prefix = Path.home() / ".local" / "share" / "ecosystem"
    if filename == "ecosystem-ui-controls.js":
        candidates.append(local_prefix / "packages" / "ecosystem-ui-controls" / "dist" / "ecosystem-ui-controls.js")
    elif filename == "ecosystem-theme.css":
        candidates.append(local_prefix / "theme" / "ecosystem-theme.css")
    elif filename.startswith("fonts/"):
        candidates.append(local_prefix / "theme" / filename)
    for target in candidates:
        if target.is_file():
            return target
    return None


def build_cyber_agents_capabilities() -> list[dict[str, Any]]:
    """Capabilities contributed by cyber-agents (`aegissiem_daemon`) to the ecosystem mesh."""
    return [
        {
            "capability": "security.triage_threat",
            "version": 1,
            "description": "Local/brokered LLM security triage and threat classification over syslog and SIEM context.",
            "action_class": "investigate",
            "required_grant": "security:triage",
            "requirements": {"os": ["darwin", "linux", "win32"], "min_tier": 1, "needs_gpu": False},
            "timeout_seconds": 60,
            "cancellable": True,
            "idempotent": True,
            "offline_behavior": "run_local",
        },
        {
            "capability": "security.honeypot_status",
            "version": 1,
            "description": "Query active deception honeypots and captured attacker telemetry.",
            "action_class": "observe",
            "required_grant": "security:read",
            "timeout_seconds": 15,
            "cancellable": True,
            "idempotent": True,
            "offline_behavior": "run_local",
        },
        {
            "capability": "ecosystem.freeze",
            "version": 1,
            "description": "Propagate immediate emergency Freeze to cyber-agents response & auto-block pipelines.",
            "action_class": "contain",
            "required_grant": "policy:freeze",
            "timeout_seconds": 5,
            "cancellable": False,
            "idempotent": True,
            "offline_behavior": "run_local",
        },
    ]


def threat_dedupe_key(threat: Any) -> str:
    """Shared deterministic dedupe key across cyber-agents and AegisSIEM."""
    ts = getattr(threat, "timestamp", "")
    hour_bucket = ts.strftime("%Y%m%d%H") if hasattr(ts, "strftime") else str(ts)[:13]
    source_ip = getattr(threat, "source_ip", None) or "unknown"
    threat_type = getattr(threat, "threat_type", None) or "unknown"
    return f"aegissiem:{threat_type}:{source_ip}:{hour_bucket}"


def _threat_severity_str(threat: Any) -> str:
    sev = getattr(threat, "severity", None)
    raw = str(getattr(sev, "value", sev) or "medium").strip().lower()
    return raw if raw in ("low", "medium", "high", "critical") else "medium"


async def start_daemon_hub(api_port: int) -> Any:
    """Start HubRuntime for `aegissiem_daemon` (priority=15, default role='join')."""
    global _active_hub
    _ensure_ecosystem_paths()
    from ecosystem_hub import HubRuntime

    hub = HubRuntime(
        app_name="aegissiem_daemon",
        service_port=api_port,
        priority=15,
        role=os.environ.get("ECOSYSTEM_HUB_ROLE", "join"),
        health_endpoint="/api/status",
        capabilities=build_cyber_agents_capabilities(),
    )
    mode = await hub.start()
    _active_hub = hub
    logger.info("cyber-agents HubRuntime active in %s mode (role=%s)", mode, hub.role.value)
    return hub


async def stop_daemon_hub() -> None:
    global _active_hub
    hub = _active_hub
    _active_hub = None
    if hub is not None:
        try:
            await hub.stop()
        except Exception as exc:
            logger.debug("Error stopping cyber-agents HubRuntime: %r", exc)


async def publish_threat_notification(threat: Any, *, hub: Any = None) -> dict[str, Any] | None:
    """Publish a deduplicated `notify.security` envelope via HubRuntime (or queue offline)."""
    target_hub = hub or _active_hub
    if target_hub is None:
        return None
    sev = _threat_severity_str(threat)
    source_ip = getattr(threat, "source_ip", None) or "N/A"
    threat_type = getattr(threat, "threat_type", None) or "threat"
    router_name = getattr(threat, "router_name", None) or "N/A"
    title = f"AegisSIEM {sev.upper()} Threat: {threat_type}"
    body = f"Type: {threat_type} | Source IP: {source_ip} | Router: {router_name}"
    return await target_hub.notify(
        "notify.security",
        sev,
        title,
        body,
        dedupe_key=threat_dedupe_key(threat),
        privacy="redacted",
    )


def publish_threat_notification_sync(threat: Any, *, hub: Any = None) -> dict[str, Any] | None:
    """Best-effort synchronous wrapper callable from sync `daemon.notifications.notify()`."""
    target_hub = hub or _active_hub
    if target_hub is None:
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    try:
        if loop is not None and loop.is_running():
            loop.create_task(publish_threat_notification(threat, hub=target_hub))
            return {"status": "scheduled", "dedupe_key": threat_dedupe_key(threat)}
        return asyncio.run(publish_threat_notification(threat, hub=target_hub))
    except Exception as exc:
        logger.debug("publish_threat_notification_sync skipped: %r", exc)
        return None
