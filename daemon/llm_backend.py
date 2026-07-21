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


class AnalysisUnavailable(RuntimeError):
    """No configured provider could answer the request."""


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


def _build_router():
    """Construct a ProviderRouter from the current ecosystem AI profile.

    Uses AIProfile.from_dict rather than the dataclass constructor: from_dict is
    what correctly rebuilds the nested `cloud` mapping into CloudProvider
    objects. Passing the raw dict through cls(**...) would leave plain dicts
    there and build_providers() would fail on cfg.enabled.
    """
    from ecosystem_ai import AIProfile, build_router

    profile = AIProfile.from_dict(_load_profile_dict())
    return build_router(profile)


def describe_backend() -> dict[str, Any]:
    """Non-secret description of the active backend. Safe to log or return."""
    prof = _load_profile_dict()
    return {
        "provider": prof.get("default_provider", "ollama"),
        "model": prof.get("selected_model", "auto"),
        "allow_cloud_fallback": prof.get("allow_cloud_fallback", True),
    }


async def analyze(prompt: str, context: Optional[str] = None) -> tuple[str, str, str]:
    """Run a security-analysis completion through the selected provider.

    Returns (text, model, provider) so the caller can report which backend
    actually served the request.
    """
    if context:
        prompt = f"{prompt}\n\nAdditional context:\n{context}"

    from ecosystem_ai import ChatMessage

    try:
        router = _build_router()
        result = await router.chat([ChatMessage(role="user", content=prompt)], task="chat")
    except Exception as e:
        # Never surface provider credentials or raw response bodies to the caller.
        logger.warning("LLM analysis failed: %s: %s", e.__class__.__name__, e)
        raise AnalysisUnavailable(
            "No configured AI provider could complete the request"
        ) from e

    return result.text, result.model, result.provider
