"""LLM access for the harness daemon, driven by the ecosystem AI profile.

The daemon previously called Ollama directly via OLLAMA_HOST, which meant a user
who selected Claude/Gemini/OpenAI in the ecosystem AI profile was silently
ignored here. This routes analysis through ecosystem_ai's ProviderRouter so the
selected provider is honoured.

This module is a pure CONSUMER of the profile: it never writes it, so it cannot
disturb the local model selection AI-for-Survival manages. Ollama remains the
default; a cloud provider is only used when explicitly enabled in the profile.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

REGISTRY_URL = os.environ.get("ECOSYSTEM_REGISTRY_URL", "http://localhost:8500")
_PROFILE_TIMEOUT = 4.0


# Capability verdict from the most recent routed call, surfaced to API callers
# so a weak-model warning reaches the user rather than only the daemon log.
_last_capability: dict = {"v": None}


def last_capability() -> Optional[dict]:
    return _last_capability.get("v")


class AnalysisUnavailable(RuntimeError):
    """No configured provider could answer the request."""


class AnalysisNotLocal(AnalysisUnavailable):
    """A local-only analysis was asked for, but the AI profile could reach a cloud provider."""


def _load_profile_dict() -> dict[str, Any]:
    """Fetch the ecosystem AI profile, falling back to local defaults.

    A missing/unreachable registry is normal for a standalone install, so that
    degrades to the packaged defaults rather than failing.
    """
    try:
        import httpx

        r = httpx.get(f"{REGISTRY_URL}/ai-profile", timeout=_PROFILE_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            # The registry may wrap the profile; accept either shape.
            return data.get("profile", data) if isinstance(data, dict) else {}
    except Exception as e:
        logger.debug("Could not fetch ai-profile from registry: %s", e.__class__.__name__)
    return {}


def _build_router(profile_dict: Optional[dict[str, Any]] = None):
    """Construct a ProviderRouter from the ecosystem AI profile (fetched unless given).

    Uses AIProfile.from_dict rather than the dataclass constructor: from_dict is
    what correctly rebuilds the nested `cloud` mapping into CloudProvider
    objects. Passing the raw dict through cls(**...) would leave plain dicts
    there and build_providers() would fail on cfg.enabled.
    """
    from ecosystem_ai import AIProfile, build_router

    profile = AIProfile.from_dict(_load_profile_dict() if profile_dict is None else profile_dict)
    return build_router(profile)


LOCAL_PROVIDERS = frozenset({"ollama"})


def security_analysis_stays_local(profile: Optional[dict[str, Any]] = None) -> bool:
    """True only when a `security` analysis can run on nothing but a local model.

    Mirrors ecosystem_ai's provider order for the task: a per-task pin wins,
    else `prefer: cloud` puts enabled cloud providers first, else the default
    provider. Cloud fallback with any cloud provider enabled could also send
    the prompt off the device, so that is not local either. An unreadable
    profile falls back to the packaged defaults (Ollama, no cloud), as
    `analyze` itself does.
    """
    from ecosystem_ai import AIProfile

    prof = AIProfile.from_dict(profile if profile is not None else _load_profile_dict())
    cloud_enabled = [name for name, cfg in (prof.cloud or {}).items() if getattr(cfg, "enabled", False)]
    pinned = (getattr(prof, "task_providers", {}) or {}).get("security") or ""
    if pinned:
        first = pinned
    elif prof.prefer == "cloud" and cloud_enabled:
        first = cloud_enabled[0]
    else:
        first = prof.default_provider
    if first not in LOCAL_PROVIDERS:
        return False
    return not (prof.allow_cloud_fallback and cloud_enabled)


def describe_backend() -> dict[str, Any]:
    """Non-secret description of the active backend. Safe to log or return."""
    prof = _load_profile_dict()
    desc = {
        "provider": prof.get("default_provider", "ollama"),
        "model": prof.get("selected_model", "auto"),
        "allow_cloud_fallback": prof.get("allow_cloud_fallback", False),
    }
    try:
        from ecosystem_compute import diagnose_gpu
        diag = diagnose_gpu()
        desc["accelerator"] = diag.hardware_accelerator
        desc["status"] = diag.status
    except Exception:
        pass
    return desc


def _local_only_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """`profile` with every route off the device removed: no cloud provider, no fallback."""
    forced = dict(profile or {})
    forced["cloud"] = {
        name: {**(cfg or {}), "enabled": False}
        for name, cfg in (forced.get("cloud") or {}).items()
        if isinstance(cfg, dict)
    }
    forced["allow_cloud_fallback"] = False
    forced["prefer"] = "local"
    return forced


async def analyze(
    prompt: str, context: Optional[str] = None, *, local_only: bool = False
) -> tuple[str, str, str]:
    """Run a security-analysis completion through the selected provider.

    Returns (text, model, provider) so the caller can report which backend
    actually served the request.

    `local_only=True` loads the profile once, refuses (AnalysisNotLocal) if that
    profile could send the analysis off the device, and builds the router from
    the same profile with every cloud provider and fallback switched off, so
    the check and the call cannot disagree.
    """
    if context:
        prompt = f"{prompt}\n\nAdditional context:\n{context}"

    from ecosystem_ai import ChatMessage

    profile_dict = None
    if local_only:
        profile_dict = _load_profile_dict()
        if not security_analysis_stays_local(profile_dict):
            raise AnalysisNotLocal(
                "this analysis runs only on a local model; the AI profile could send it to a cloud provider"
            )
        profile_dict = _local_only_profile(profile_dict)

    try:
        router = _build_router() if profile_dict is None else _build_router(profile_dict)
        # task="security": this daemon IS the security-analysis backend, so the
        # router applies security routing AND its model-capability check here.
        result = await router.chat([ChatMessage(role="user", content=prompt)], task="security")
        _last_capability["v"] = getattr(router, "last_capability", None)
    except Exception as e:
        # Never surface provider credentials or raw response bodies to the caller.
        logger.warning("LLM analysis failed: %s: %s", e.__class__.__name__, e)
        raise AnalysisUnavailable(
            "No configured AI provider could complete the request"
        ) from e

    if local_only and result.provider not in LOCAL_PROVIDERS:
        # Unreachable with the forced profile; kept so a router change cannot
        # silently turn a local-only analysis into a cloud one.
        raise AnalysisNotLocal(f"a local-only analysis was answered by '{result.provider}'")
    return result.text, result.model, result.provider
