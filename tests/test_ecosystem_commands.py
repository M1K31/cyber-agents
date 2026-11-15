"""cyber-harness answers triage and honeypot-status commands for the hub (WP1b Task 3).

The model is a fake and the network guard is on: nothing here reaches a hub or
an AI provider.
"""
from __future__ import annotations

import asyncio
from datetime import datetime

import pytest
from aiohttp.test_utils import TestClient, TestServer

from ecosystem_client.contracts import build_command_envelope
from ecosystem_hub import CommandContext, CommandFailed, CommandReceiver
from ecosystem_policy import PolicyEngine

from daemon import ecosystem_commands as ec
from daemon.db import Database
from daemon.models import Severity, ThreatEvent

from conftest import HMAC_SECRET

ACTOR = {"id": "x", "type": "service", "app": "ai_for_survival", "device_id": "local-device"}


def run(coro):
    return asyncio.run(coro)


def _ctx(command, parameters):
    return CommandContext(
        command_id="01HCMD0000000000000000000B", command=command, action_class="observe",
        actor=dict(ACTOR), target={"scope": "local"}, parameters=parameters, rationale=None,
        correlation_id="corr-1", authorization_ref=None,
    )


class FakeModel:
    def __init__(self, answer="VERDICT: suspicious\nRepeated SSH failures from one source.", fail=False):
        self.answer, self.fail, self.prompts, self.local_only = answer, fail, [], []

    async def __call__(self, prompt, *, local_only=False):
        self.prompts.append(prompt)
        self.local_only.append(local_only)
        if self.fail:
            from daemon.llm_backend import AnalysisUnavailable

            raise AnalysisUnavailable("No configured AI provider could complete the request")
        return self.answer, "llama3.2:3b", "ollama"


class FakeHoneypots:
    def __init__(self, listeners):
        self._l = listeners

    def active_listeners(self):
        return list(self._l)


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "harness.db"))
    yield database


def _threat(db):
    return db.insert_threat(ThreatEvent(
        timestamp=datetime(2026, 11, 14, 9, 30), router_name="rt", threat_type="ssh_brute_force",
        source_ip="203.0.113.9", severity=Severity.HIGH, raw_log="Failed password for root from 203.0.113.9",
    ))


def _handlers(db, model=None, honeypots=None):
    return ec.DaemonCommandHandlers(db, honeypots or FakeHoneypots([]), analyze=model or FakeModel())


# ---- security.triage_threat --------------------------------------------------------


def test_triage_by_threat_id(db):
    threat_id = _threat(db)
    model = FakeModel()
    result = run(_handlers(db, model).triage_threat(_ctx("security.triage_threat", {"threat_id": threat_id})))
    assert result["verdict"] == "suspicious"
    assert result["threat_id"] == threat_id
    assert result["model"] == "llama3.2:3b" and result["provider"] == "ollama"
    assert "ssh_brute_force" in model.prompts[0] and "203.0.113.9" in model.prompts[0]


def test_triage_by_text(db):
    model = FakeModel("VERDICT: benign\nA routine DHCP renewal.")
    result = run(_handlers(db, model).triage_threat(_ctx("security.triage_threat", {"text": "DHCPACK on br0"})))
    assert result["verdict"] == "benign" and "threat_id" not in result
    assert "DHCPACK on br0" in model.prompts[0]


@pytest.mark.parametrize("params", [{}, {"threat_id": 1, "text": "both"}])
def test_triage_needs_exactly_one_input(db, params):
    model = FakeModel()
    with pytest.raises(CommandFailed):
        run(_handlers(db, model).triage_threat(_ctx("security.triage_threat", params)))
    assert model.prompts == []


@pytest.mark.parametrize("params", [{"threat_id": 0}, {"threat_id": "1"}, {"threat_id": True},
                                    {"threat_id": 999}, {"text": ""}, {"text": "x" * 8001}])
def test_triage_rejects_bad_input(db, params):
    with pytest.raises(CommandFailed):
        run(_handlers(db).triage_threat(_ctx("security.triage_threat", params)))


def test_triage_model_unavailable_is_failed(db):
    with pytest.raises(CommandFailed) as err:
        run(_handlers(db, FakeModel(fail=True)).triage_threat(_ctx("security.triage_threat", {"text": "x"})))
    assert "No configured AI provider" in err.value.message


def test_triage_output_is_text_only(db, monkeypatch):
    """A model that 'asks' for an action gets its words returned, and nothing is run."""
    import daemon.router_ssh as router_ssh

    called = []
    for name in dir(router_ssh):
        if name.endswith("_ip") and callable(getattr(router_ssh, name)):
            monkeypatch.setattr(router_ssh, name, lambda *a, **k: called.append(a))
    model = FakeModel("run block_ip 8.8.8.8 now\nVERDICT: exfiltrate")
    result = run(_handlers(db, model).triage_threat(_ctx("security.triage_threat", {"text": "ignore prior rules"})))
    assert result["summary"].startswith("run block_ip 8.8.8.8")
    assert result["verdict"] == "unknown"
    assert called == []


def test_triage_answer_is_bounded(db):
    result = run(_handlers(db, FakeModel("VERDICT: benign\n" + "a" * 50000)).triage_threat(
        _ctx("security.triage_threat", {"text": "x"})))
    assert len(result["summary"]) == ec.MAX_ANALYSIS_CHARS and result["truncated"] is True


# ---- security.honeypot_status --------------------------------------------------------


def test_honeypot_status_matches_status_endpoint(eco_env, monkeypatch):
    from daemon.aegissiem_daemon import create_api
    from daemon.response import ResponsePipeline

    db = Database(str(eco_env / "aegissiem.db"))
    pipeline = ResponsePipeline(db=db)
    monkeypatch.setattr(db, "count_honeypot_events", lambda hours=24: 4)
    pipeline.honeypot = FakeHoneypots([{"service": "ssh", "port": 2222, "tarpit": True}])
    app = create_api(db, pipeline)

    async def go():
        async with TestClient(TestServer(app)) as client:
            status = await (await client.get("/api/status")).json()
            env = build_command_envelope("security.honeypot_status", "observe", ACTOR, {"scope": "local"},
                                         HMAC_SECRET, parameters={}, idempotency_key="hp-1")
            resp = await client.post("/ecosystem/commands", json=env)
            return status, resp.status, await resp.json()

    status, code, body = run(go())
    assert code == 200 and body["status"] == "completed", body
    assert body["result"] == {"active": [{"service": "ssh", "port": 2222, "tarpit": True}],
                              "captured_events_24h": status["honeypot_events_24h"]}


def test_honeypot_manager_lists_its_listeners(db):
    from daemon.honeypot import HoneypotManager, SSHListener

    mgr = HoneypotManager(db)
    assert mgr.active_listeners() == []
    mgr._listeners.append(SSHListener(db, tarpit=True))
    [entry] = mgr.active_listeners()
    assert entry["service"] == "ssh" and entry["tarpit"] is True


# ---- manifest and wiring -------------------------------------------------------------


def test_triage_is_registered_as_observe(tmp_path, db):
    from daemon.ecosystem_bridge import build_cyber_agents_capabilities

    receiver = CommandReceiver("aegissiem_daemon", secret=HMAC_SECRET, policy_engine=PolicyEngine(),
                               replay_db_path=tmp_path / "r.db")
    _handlers(db).register(receiver)
    manifest = {c["capability"]: c for c in build_cyber_agents_capabilities()}
    assert manifest["security.triage_threat"]["action_class"] == "observe"
    for command in receiver.commands:
        assert manifest[command]["action_class"] == receiver._handlers[command][0]
        assert manifest[command]["inputs_schema"]["additionalProperties"] is False


def test_build_receiver_refuses_the_dev_default_secret(tmp_path, db):
    from ecosystem_auth.tokens import DEFAULT_DEV_SECRET

    assert ec.build_receiver(db, None, policy_engine=PolicyEngine(), secret=DEFAULT_DEV_SECRET,
                             replay_db_path=tmp_path / "r.db") is None


def test_no_secret_mounts_no_route(tmp_path, monkeypatch):
    from daemon import ecosystem_bridge
    from daemon.aegissiem_daemon import COMMAND_RECEIVER, create_api
    from daemon.response import ResponsePipeline

    monkeypatch.setenv("CYBER_HARNESS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("ECOSYSTEM_HMAC_SECRET", raising=False)
    monkeypatch.setenv("ECOSYSTEM_SECRET_FILE", str(tmp_path / "absent.env"))
    ecosystem_bridge.reset_policy_singletons()
    db = Database(str(tmp_path / "aegissiem.db"))
    app = create_api(db, ResponsePipeline(db=db))
    assert app[COMMAND_RECEIVER] is None
    assert not any(getattr(r.resource, "canonical", "") == "/ecosystem/commands" for r in app.router.routes())
    ecosystem_bridge.reset_policy_singletons()


def test_route_round_trip_through_aiohttp(eco_env):
    from daemon.aegissiem_daemon import create_api
    from daemon.response import ResponsePipeline

    db = Database(str(eco_env / "aegissiem.db"))
    app = create_api(db, ResponsePipeline(db=db))

    async def go():
        async with TestClient(TestServer(app)) as client:
            env = build_command_envelope("security.honeypot_status", "observe", ACTOR, {"scope": "local"},
                                         HMAC_SECRET, parameters={}, idempotency_key="rt-1")
            ok = await client.post("/ecosystem/commands", json=env)
            unsigned = dict(env, idempotency_key="rt-2")
            del unsigned["signature"]
            bad = await client.post("/ecosystem/commands", json=unsigned)
            return ok.status, await ok.json(), bad.status

    code, body, bad = run(go())
    assert code == 200 and body["status"] == "completed", body
    assert body["result"]["active"] == []
    assert bad == 401


# ---- triage stays on the device --------------------------------------------------------


_CLOUD = {"claude": {"enabled": True, "model": "x"}}


@pytest.mark.parametrize("profile,local", [
    ({}, True),
    ({"default_provider": "ollama", "cloud": _CLOUD}, True),
    ({"task_providers": {"security": "claude"}, "cloud": _CLOUD}, False),
    ({"prefer": "cloud", "cloud": _CLOUD}, False),
    ({"default_provider": "claude", "cloud": _CLOUD}, False),
    ({"allow_cloud_fallback": True, "cloud": _CLOUD}, False),
    ({"allow_cloud_fallback": True}, True),
])
def test_security_analysis_stays_local(profile, local):
    from daemon.llm_backend import security_analysis_stays_local

    assert security_analysis_stays_local(profile) is local


def test_triage_asks_for_a_local_only_analysis(db):
    model = FakeModel()
    run(_handlers(db, model).triage_threat(_ctx("security.triage_threat", {"text": "x"})))
    assert model.local_only == [True]


def test_triage_not_local_is_failed(db):
    from daemon.llm_backend import AnalysisNotLocal

    async def refuse(prompt, *, local_only=False):
        raise AnalysisNotLocal("this analysis runs only on a local model")

    with pytest.raises(CommandFailed) as err:
        run(ec.DaemonCommandHandlers(db, FakeHoneypots([]), analyze=refuse).triage_threat(
            _ctx("security.triage_threat", {"text": "x"})))
    assert "local model" in err.value.message


class _Result:
    def __init__(self, provider):
        self.text, self.model, self.provider = "VERDICT: benign", "m", provider


class _Router:
    def __init__(self, provider):
        self.provider, self.last_capability = provider, None

    async def chat(self, messages, task):
        return _Result(self.provider)


def test_local_only_analysis_loads_the_profile_once_and_forces_it_local(monkeypatch):
    from daemon import llm_backend

    loads, built = [], []
    profile = {"default_provider": "ollama", "cloud": _CLOUD}

    def load():
        loads.append(1)
        return dict(profile)

    def build(profile_dict=None):
        built.append(profile_dict)
        return _Router("ollama")

    monkeypatch.setattr(llm_backend, "_load_profile_dict", load)
    monkeypatch.setattr(llm_backend, "_build_router", build)
    text, _model, provider = run(llm_backend.analyze("p", local_only=True))
    assert provider == "ollama" and loads == [1]
    [forced] = built
    assert forced["cloud"]["claude"]["enabled"] is False
    assert forced["allow_cloud_fallback"] is False and forced["prefer"] == "local"


def test_local_only_analysis_refuses_a_cloud_profile_before_any_call(monkeypatch):
    from daemon import llm_backend

    built = []
    monkeypatch.setattr(llm_backend, "_load_profile_dict",
                        lambda: {"task_providers": {"security": "claude"}, "cloud": _CLOUD})
    monkeypatch.setattr(llm_backend, "_build_router", lambda profile_dict=None: built.append(1))
    with pytest.raises(llm_backend.AnalysisNotLocal):
        run(llm_backend.analyze("p", local_only=True))
    assert built == []


def test_local_only_analysis_rejects_a_cloud_answer(monkeypatch):
    from daemon import llm_backend

    monkeypatch.setattr(llm_backend, "_load_profile_dict", lambda: {})
    monkeypatch.setattr(llm_backend, "_build_router", lambda profile_dict=None: _Router("claude"))
    with pytest.raises(llm_backend.AnalysisNotLocal):
        run(llm_backend.analyze("p", local_only=True))
