"""The daemon's LLM backend follows the ecosystem AI profile.

The daemon used to call Ollama directly, so a user who selected Claude/Gemini/
OpenAI in the shared profile was silently ignored. These tests pin the contract:
analysis goes through ecosystem_ai's router, failures surface as
AnalysisUnavailable rather than leaking provider errors, and the module never
writes the profile (which would fight AI-for-Survival's model selection).
"""
import pytest

from daemon import llm_backend


class _FakeResult:
    def __init__(self, text="analysis-result", model="phi3", provider="ollama"):
        self.text = text
        self.model = model
        self.provider = provider


class _FakeRouter:
    def __init__(self, result=None):
        self.result = result or _FakeResult()
        self.calls = []

    async def chat(self, messages, task="chat", **kw):
        self.calls.append((messages, task))
        return self.result


@pytest.mark.asyncio
async def test_analyze_routes_through_the_router(monkeypatch):
    fake = _FakeRouter()
    monkeypatch.setattr(llm_backend, "_build_router", lambda: fake)

    text, model, provider = await llm_backend.analyze("threat prompt")

    assert (text, model, provider) == ("analysis-result", "phi3", "ollama")
    # One user message carrying the prompt.
    messages, task = fake.calls[0]
    # This daemon IS the security-analysis backend, so it routes as "security":
    # that applies the user's security provider pin AND the model-capability check.
    assert task == "security"
    assert len(messages) == 1
    assert messages[0].role == "user"
    assert messages[0].content == "threat prompt"


@pytest.mark.asyncio
async def test_context_is_appended_to_the_prompt(monkeypatch):
    fake = _FakeRouter()
    monkeypatch.setattr(llm_backend, "_build_router", lambda: fake)

    await llm_backend.analyze("base prompt", context="extra detail")

    content = fake.calls[0][0][0].content
    assert "base prompt" in content
    assert "extra detail" in content


@pytest.mark.asyncio
async def test_provider_failure_becomes_AnalysisUnavailable(monkeypatch):
    class _Broken:
        async def chat(self, messages, task="chat", **kw):
            raise RuntimeError("provider exploded: key sk-test-should-not-leak")

    monkeypatch.setattr(llm_backend, "_build_router", lambda: _Broken())

    with pytest.raises(llm_backend.AnalysisUnavailable) as exc:
        await llm_backend.analyze("x")

    # The caller-facing message must not carry the provider's raw error text,
    # which could contain credentials.
    assert "sk-test-should-not-leak" not in str(exc.value)


def test_describe_backend_reports_provider_and_no_secrets(monkeypatch):
    monkeypatch.setattr(
        llm_backend, "_load_profile_dict",
        lambda: {"default_provider": "anthropic", "selected_model": "claude-sonnet-4-5"},
    )
    desc = llm_backend.describe_backend()

    assert desc["provider"] == "anthropic"
    assert desc["model"] == "claude-sonnet-4-5"
    assert not any("key" in k.lower() for k in desc)


def test_profile_fetch_failure_falls_back_to_defaults(monkeypatch):
    """A standalone install with no registry must still describe a backend."""
    monkeypatch.setattr(llm_backend, "REGISTRY_URL", "http://127.0.0.1:9")  # closed port
    desc = llm_backend.describe_backend()
    assert desc["provider"] == "ollama"


def test_daemon_never_writes_the_ai_profile():
    """This module must be read-only w.r.t. the shared profile.

    Writing it would fight AI-for-Survival, which owns local model selection.
    """
    import inspect

    src = inspect.getsource(llm_backend)
    assert ".put(" not in src
    assert "update_ai_profile" not in src
