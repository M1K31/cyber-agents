"""AegisSIEM Daemon - Main entry point.

Async event loop that:
1. Loads config from ~/.aegissiem-daemon/config.yml
2. Calls ensure-ollama.sh
3. Initializes Database, DetectionEngine, ResponsePipeline, HoneypotManager
4. Starts syslog file watcher (watchdog) or UDP listener
5. Processes events through detection -> response pipeline
6. Runs auto_block_loop as background task
7. Runs daily summary scheduler as background task
8. Serves HTTP API on port 8088 using aiohttp for the dashboard
9. Writes threat data as JSON to vault/threat-data/ directory
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import signal
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import yaml
import aiohttp
from aiohttp import web
try:
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - optional when running UDP/API-only
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    FileModifiedEvent = object  # type: ignore[assignment,misc]
    Observer = None  # type: ignore[assignment,misc]

from .db import Database
from .detection import DetectionEngine
from .honeypot import HoneypotManager
from .models import ThreatStatus
from .response import ResponsePipeline
from .syslog_parser import parse_line

logger = logging.getLogger("aegissiem")

CONFIG_PATH = Path.home() / ".aegissiem-daemon" / "config.yml"
VAULT_THREAT_DIR = Path.home() / ".aegissiem-daemon" / "vault" / "threat-data"


def load_config(path: Path = CONFIG_PATH) -> dict:
    """Load YAML configuration file."""
    if not path.exists():
        logger.warning("Config file not found at %s, using defaults", path)
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def ensure_ollama(config: dict):
    """Call ensure-ollama.sh if configured."""
    script = config.get("ollama_script")
    if script and Path(script).exists():
        try:
            result = subprocess.run(
                [str(script)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Ollama check passed")
            else:
                logger.warning("Ollama check failed: %s", result.stderr)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("Could not run ensure-ollama.sh: %s", e)


def write_threat_json(threats: list[dict], output_dir: Path = VAULT_THREAT_DIR):
    """Write threat data as JSON to vault/threat-data/ directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"threats_{timestamp}.json"
    with open(path, "w") as f:
        json.dump(threats, f, indent=2, default=str)
    logger.info("Wrote threat data to %s", path)


# ── Syslog File Watcher ────────────────────────────────────────────

class SyslogFileHandler(FileSystemEventHandler):
    """Watchdog handler that tails a syslog file for new lines."""

    def __init__(self, engine: DetectionEngine, pipeline: ResponsePipeline, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.engine = engine
        self.pipeline = pipeline
        self.loop = loop
        self._position: int = 0
        self._path: Optional[str] = None

    def set_file(self, path: str):
        self._path = path
        try:
            self._position = Path(path).stat().st_size
        except OSError:
            self._position = 0

    def on_modified(self, event):
        if not isinstance(event, FileModifiedEvent):
            return
        if self._path and event.src_path == self._path:
            self._read_new_lines()

    def _read_new_lines(self):
        if not self._path:
            return
        try:
            with open(self._path, "r") as f:
                f.seek(self._position)
                new_lines = f.readlines()
                self._position = f.tell()
        except OSError:
            return

        for line in new_lines:
            event = parse_line(line)
            if event:
                self.engine.db.insert_log_event(event)
                threats = self.engine.process_event(event)
                for threat in threats:
                    asyncio.run_coroutine_threadsafe(
                        self.pipeline.handle_threat(threat), self.loop
                    )


# ── UDP Syslog Listener ────────────────────────────────────────────

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """UDP syslog receiver."""

    def __init__(self, engine: DetectionEngine, pipeline: ResponsePipeline):
        self.engine = engine
        self.pipeline = pipeline

    def datagram_received(self, data: bytes, addr: tuple):
        line = data.decode(errors="replace").strip()
        event = parse_line(line)
        if event:
            self.engine.db.insert_log_event(event)
            threats = self.engine.process_event(event)
            for threat in threats:
                asyncio.ensure_future(self.pipeline.handle_threat(threat))


# ── HTTP API (aiohttp) ─────────────────────────────────────────────

def _duration_to_seconds(raw: Any) -> tuple[int | None, bool]:
    if raw == "until_revoked":
        return None, True
    if isinstance(raw, (int, float)):
        return max(60, int(raw)), False
    s = str(raw or "30m").strip().lower()
    mapping = {"15m": 900, "30m": 1800, "1h": 3600, "4h": 14400}
    if s in mapping:
        return mapping[s], False
    if s.endswith("m") and s[:-1].isdigit():
        return max(60, int(s[:-1]) * 60), False
    if s.endswith("h") and s[:-1].isdigit():
        return max(60, int(s[:-1]) * 3600), False
    if s.isdigit():
        return max(60, int(s)), False
    return 1800, False


def _is_loopback_request(request: web.Request) -> bool:
    if request.headers.get("X-Forwarded-For"):
        return False
    remote = str(request.remote or "").strip()
    return remote in ("127.0.0.1", "::1", "localhost", "")


async def _read_json_optional(request: web.Request) -> dict[str, Any]:
    if not request.can_read_body:
        return {}
    try:
        raw = await request.text()
        if not raw.strip():
            return {}
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def create_api(db: Database, pipeline: ResponsePipeline, *, step_up_auth: Any = None) -> web.Application:
    """Create the aiohttp web application with API routes, step-up auth, and policy controls."""
    from .ecosystem_bridge import (
        _ensure_ecosystem_paths,
        get_step_up_auth,
        resolve_ui_asset_path,
    )

    _ensure_ecosystem_paths()
    from ecosystem_auth.tokens import NonceStore, get_ecosystem_secret, verify_request

    app = web.Application()
    nonce_store = NonceStore(ttl_seconds=600)
    step_up = step_up_auth or get_step_up_auth()
    policy_engine = pipeline.policy_engine

    def _verify_hmac_peer(request: web.Request, body: dict[str, Any] | None) -> bool:
        sig = request.headers.get("X-Ecosystem-Signature")
        ts = request.headers.get("X-Ecosystem-Timestamp")
        nonce = request.headers.get("X-Ecosystem-Nonce")
        if not (sig and ts and nonce):
            return False
        try:
            secret = get_ecosystem_secret()
        except Exception:
            return False
        return verify_request(
            method=request.method,
            url=str(request.rel_url),
            secret=secret,
            signature=sig,
            timestamp=ts,
            nonce=nonce,
            body=body if body else None,
            nonce_store=nonce_store,
        )

    def _authenticate_privileged(
        request: web.Request,
        body: dict[str, Any],
        *,
        required_scope: str = "policy_admin",
    ) -> tuple[str, str, str | None] | None:
        """Verify either HMAC peer signature OR operator step-up (TOTP / Passkey / Device-Key)."""
        if _verify_hmac_peer(request, body):
            key_id = request.headers.get("X-Ecosystem-Key-Id") or "ecosystem-peer"
            return (key_id, "device_key", None)

        token = (
            str(body.get("step_up_token") or request.headers.get("X-Ecosystem-Step-Up") or "").strip()
        )
        if token:
            claims = step_up.verify_step_up_token(token, required_scope=required_scope)
            if claims:
                return (str(claims["sub"]), str(claims["amr"]), token)

        operator_id = str(body.get("operator_id") or "admin").strip()
        totp_code = str(body.get("totp_code") or body.get("step_up_credential") or "").strip()
        if totp_code and len(totp_code) == 6 and totp_code.isdigit():
            issued = step_up.verify_totp_and_issue_token(operator_id, totp_code, scope=required_scope)
            if issued:
                return (operator_id, "totp", str(issued["step_up_token"]))
        return None

    async def get_status(request: web.Request) -> web.Response:
        aggregated = db.get_threats_aggregated()
        blocked = db.get_blocked_ips()
        profiles = db.get_profiles(limit=1000)
        honeypot_events = db.get_honeypot_events(limit=1000)
        pending_approvals = db.get_pending_approvals()
        by_status = aggregated.get("by_status", {}) if isinstance(aggregated, dict) else {}
        return web.json_response({
            "status": "running",
            "threats": aggregated,
            "open_threats": by_status.get("open", 0),
            "blocked_count": len(blocked),
            "blocked_ips": len(blocked),
            "profile_count": len(profiles) if isinstance(profiles, list) else 0,
            "active_profiles": len(profiles) if isinstance(profiles, list) else 0,
            "honeypot_events_24h": len(honeypot_events),
            "pending_approvals": len(pending_approvals),
            "policy": policy_engine.export_state(),
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def get_threats(request: web.Request) -> web.Response:
        status_filter = request.query.get("status")
        limit = int(request.query.get("limit", "100"))
        threats = db.get_threats(status=status_filter, limit=limit)
        return web.json_response([t.model_dump(mode="json") for t in threats])

    async def post_block_threat(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        auth_info = _authenticate_privileged(request, body)
        if auth_info is None:
            return web.json_response(
                {"status": "unauthorized", "detail": "HMAC service signature or TOTP step-up required"},
                status=401,
            )
        threat_id = int(request.match_info["id"])
        success = await pipeline.block_threat(threat_id)
        if success:
            return web.json_response({"status": "blocked", "threat_id": threat_id})
        if policy_engine.export_state().get("frozen"):
            return web.json_response(
                {"status": "frozen", "detail": "Ecosystem Freeze is active; mutating blocks are suspended"},
                status=409,
            )
        return web.json_response({"status": "failed", "threat_id": threat_id}, status=500)

    async def post_resolve_threat(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        if not _is_loopback_request(request) and _authenticate_privileged(request, body) is None:
            return web.json_response({"status": "unauthorized"}, status=401)
        threat_id = int(request.match_info["id"])
        db.update_threat_status(threat_id, ThreatStatus.resolved)
        return web.json_response({"status": "resolved", "threat_id": threat_id})

    async def get_profiles(request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", "100"))
        profiles = db.get_profiles(limit=limit)
        return web.json_response([p.model_dump(mode="json") for p in profiles])

    async def get_honeypot_events(request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", "100"))
        events = db.get_honeypot_events(limit=limit)
        return web.json_response([e.model_dump(mode="json") for e in events])

    async def get_approvals(request: web.Request) -> web.Response:
        pipeline.approval_manager.expire_due()
        pending = db.get_pending_approvals()
        profiles_by_id = {p.id: p for p in db.get_profiles(limit=500) if p.id is not None}
        payload = []
        for a in pending:
            prof = profiles_by_id.get(a.profile_id)
            payload.append({
                "id": a.id,
                "profile_id": a.profile_id,
                "action": a.action,
                "checkpoint": a.action,
                "status": a.status,
                "reason": a.summary,
                "summary": a.summary,
                "created_at": a.created_at.isoformat(),
                "profile_summary": {
                    "ip": prof.ip,
                    "escalation_level": getattr(prof.escalation_level, "value", prof.escalation_level),
                    "total_attempts": prof.total_attempts,
                    "country": prof.country,
                } if prof else {},
            })
        return web.json_response(payload)

    async def post_approve(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        auth_info = _authenticate_privileged(request, body)
        if auth_info is None:
            return web.json_response(
                {"status": "unauthorized", "detail": "Step-up TOTP/Passkey or signed peer auth required to approve"},
                status=401,
            )
        operator_id, auth_method, token = auth_info
        approval_id = int(request.match_info["id"])
        success = pipeline.approval_manager.approve(
            approval_id,
            step_up_token=token,
            resolved_by=operator_id,
            auth_method=auth_method,
            note=str(body.get("note") or ""),
        )
        if success:
            return web.json_response({"status": "approved", "id": approval_id})
        if policy_engine.export_state().get("frozen"):
            return web.json_response(
                {"status": "frozen", "detail": "Cannot approve actions while Ecosystem Freeze is active"},
                status=409,
            )
        return web.json_response({"status": "not_found_or_not_pending"}, status=404)

    async def post_deny(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        auth_info = _authenticate_privileged(request, body)
        if auth_info is None:
            return web.json_response(
                {"status": "unauthorized", "detail": "Step-up TOTP/Passkey or signed peer auth required to deny"},
                status=401,
            )
        operator_id, auth_method, token = auth_info
        approval_id = int(request.match_info["id"])
        success = pipeline.approval_manager.deny(
            approval_id,
            step_up_token=token,
            resolved_by=operator_id,
            auth_method=auth_method,
            note=str(body.get("note") or ""),
        )
        if success:
            return web.json_response({"status": "denied", "id": approval_id})
        return web.json_response({"status": "not_found_or_not_pending"}, status=404)

    async def get_blocked(request: web.Request) -> web.Response:
        blocked = db.get_blocked_ips()
        out = []
        for b in blocked:
            d = b.model_dump(mode="json")
            d.setdefault("router", b.router_name)
            out.append(d)
        return web.json_response(out)

    async def post_unblock(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        auth_info = _authenticate_privileged(request, body)
        if auth_info is None:
            return web.json_response(
                {"status": "unauthorized", "detail": "Step-up TOTP/Passkey or signed peer auth required to unblock"},
                status=401,
            )
        raw_id = request.match_info["id"]
        target_ip = raw_id
        if raw_id.isdigit():
            for b in db.get_blocked_ips(active_only=False):
                if b.id == int(raw_id):
                    target_ip = b.ip
                    break
        # Never pass an unvalidated path segment to the router SSH unblock: a
        # value with shell metacharacters would execute on the router's account.
        # Only a well-formed IP address is ever forwarded.
        try:
            target_ip = str(ipaddress.ip_address(target_ip))
        except ValueError:
            return web.json_response(
                {"status": "error", "detail": "Invalid IP address"}, status=400
            )
        await pipeline.unblock(target_ip)
        return web.json_response({"status": "unblocked", "ip": target_ip})

    # ── Policy & Step-Up Routes ─────────────────────────────────────

    async def get_policy_state(request: web.Request) -> web.Response:
        return web.json_response(policy_engine.export_state())

    async def post_policy_freeze(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        if not _is_loopback_request(request) and not _verify_hmac_peer(request, body):
            return web.json_response({"detail": "Authentication required for remote Freeze"}, status=401)
        state = policy_engine.freeze(
            initiated_by=str(body.get("initiated_by") or "cyber-agents-operator"),
            channel=str(body.get("channel") or "dashboard"),
            reason=str(body.get("reason") or "Emergency Freeze triggered from AegisSIEM Daemon"),
            acknowledged_devices=["aegissiem_daemon"],
        )
        return web.json_response(state)

    async def post_policy_resume(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        auth_info = _authenticate_privileged(request, body)
        if auth_info is None:
            return web.json_response(
                {"detail": "Valid TOTP 2FA, Passkey, or Device-Key step-up required to Resume from Freeze"},
                status=401,
            )
        operator_id, auth_method, _ = auth_info
        state = policy_engine.resume(
            operator_id=operator_id,
            auth_method=auth_method,
            reason=str(body.get("reason") or "Operator resumed normal operation"),
        )
        return web.json_response(state)

    async def post_policy_restrictions_off(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        auth_info = _authenticate_privileged(request, body)
        if auth_info is None:
            return web.json_response(
                {"detail": "Valid TOTP 2FA, Passkey, or Device-Key step-up required for Restrictions: Off"},
                status=401,
            )
        operator_id, auth_method, _ = auth_info
        scope = body.get("scope") if isinstance(body.get("scope"), dict) else {}
        dur_sec, until_rev = _duration_to_seconds(
            "until_revoked" if body.get("until_revoked") else body.get("duration", "30m")
        )
        try:
            state = policy_engine.activate_restrictions_off(
                issued_by=operator_id,
                auth_method=auth_method,
                reason=str(body.get("reason") or ""),
                apps=list(scope.get("apps") or ["aegissiem_daemon"]),
                devices=list(scope.get("devices") or ["local"]),
                action_classes=list(scope.get("action_classes") or ["investigate", "contain"]),
                duration_seconds=dur_sec,
                until_revoked=until_rev,
                applied_devices=["aegissiem_daemon"],
            )
            return web.json_response(state)
        except (ValueError, PermissionError) as exc:
            return web.json_response({"detail": str(exc)}, status=400)

    async def post_policy_restrictions_on(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        if not _is_loopback_request(request) and _authenticate_privileged(request, body) is None:
            return web.json_response({"detail": "Authentication required"}, status=401)
        state = policy_engine.restore_restrictions_on(
            actor=str(body.get("actor") or "cyber-agents-operator"),
            reason=str(body.get("reason") or "Restored conservative policy"),
        )
        return web.json_response(state)

    async def post_totp_enroll(request: web.Request) -> web.Response:
        if not _is_loopback_request(request):
            return web.json_response({"detail": "TOTP enrollment restricted to loopback"}, status=403)
        body = await _read_json_optional(request)
        operator_id = str(body.get("operator_id") or "admin").strip()
        existing = step_up.has_enrolled_factors(operator_id)
        if existing.get("totp"):
            if _authenticate_privileged(request, body) is None:
                return web.json_response(
                    {"detail": "TOTP already enrolled; provide current TOTP code to rotate"},
                    status=401,
                )
        enrolled = step_up.enroll_totp(operator_id, issuer="AegisSIEM-Daemon")
        return web.json_response(enrolled)

    async def post_totp_verify(request: web.Request) -> web.Response:
        body = await _read_json_optional(request)
        operator_id = str(body.get("operator_id") or "admin").strip()
        code = str(body.get("totp_code") or "").strip()
        issued = step_up.verify_totp_and_issue_token(operator_id, code)
        if not issued:
            return web.json_response({"detail": "Invalid or replayed TOTP code"}, status=401)
        return web.json_response(issued)

    async def serve_ui_asset(request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        asset = resolve_ui_asset_path(name)
        if asset is None:
            return web.Response(status=404, text="UI asset not found")
        ctype = "application/javascript" if name.endswith(".js") else "text/css"
        return web.FileResponse(asset, headers={"Content-Type": ctype})

    async def serve_ui_font(request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        asset = resolve_ui_asset_path(f"fonts/{name}")
        if asset is None:
            return web.Response(status=404, text="Font asset not found")
        return web.FileResponse(asset, headers={"Content-Type": "font/woff2"})

    async def serve_dashboard_index(request: web.Request) -> web.StreamResponse:
        dash_dir = Path(__file__).resolve().parent.parent / "dashboard"
        return web.FileResponse(dash_dir / "index.html")

    async def post_analyze(request: web.Request) -> web.Response:
        """LLM-powered security analysis via Ollama.

        Accepts two calling conventions:
        - command_router: {"project", "capability", ...context}
        - llm_service:    {"prompt", "context"}
        """
        body = await request.json()

        # Build the prompt from whichever format was sent
        prompt = body.get("prompt")
        if not prompt:
            capability = body.get("capability", "threat_analysis")
            project = body.get("project", "")
            context_data = {k: v for k, v in body.items() if k not in ("project", "capability")}
            prompt = (
                f"You are a security analyst. Perform {capability} "
                f"for project '{project}'.\n\nContext:\n{json.dumps(context_data, indent=2)}"
            )

        context = body.get("context", "")
        if context:
            prompt = f"{prompt}\n\nAdditional context:\n{context}"

        # Add recent threat context from DB
        recent_threats = db.get_threats(limit=10)
        if recent_threats:
            threat_summary = "\n".join(
                f"- [{t.severity.value}] {t.threat_type} from {t.source_ip}"
                for t in recent_threats
            )
            prompt += f"\n\nRecent threats:\n{threat_summary}"

        # Route through the ecosystem provider router rather than calling Ollama
        # directly, so a user who enabled Claude/Gemini/OpenAI in the shared AI
        # profile actually gets that provider. Ollama stays the default.
        # The response shape is unchanged — command_router and llm_service
        # both consume {"status", "result", "model", "source"}.
        from .llm_backend import AnalysisUnavailable, analyze as _analyze

        try:
            text, model, provider = await _analyze(prompt)
        except AnalysisUnavailable as e:
            return web.json_response(
                {"status": "error", "error": str(e)},
                status=503,
            )
        except Exception as e:
            logger.error("Analyze endpoint failed: %s", e.__class__.__name__)
            return web.json_response(
                {"status": "error", "error": "analysis failed"},
                status=500,
            )

        # Surface the model-capability verdict. The local fallback can silently
        # land on a model too small to be trusted for security findings, and the
        # user never chose it — so it must travel with the answer, not sit in a
        # log nobody reads.
        from .llm_backend import last_capability

        payload = {
            "status": "ok",
            "result": text,
            "model": model,
            "source": "harness",
            "provider": provider,
        }
        cap = last_capability()
        if cap and cap.get("warning"):
            payload["capability_warning"] = cap["warning"]
            payload["capability_level"] = cap.get("level")
        return web.json_response(payload)

    app.router.add_get("/api/status", get_status)
    app.router.add_get("/api/threats", get_threats)
    app.router.add_post("/api/threats/{id}/block", post_block_threat)
    app.router.add_post("/api/threats/{id}/resolve", post_resolve_threat)
    app.router.add_get("/api/profiles", get_profiles)
    app.router.add_get("/api/honeypot/events", get_honeypot_events)
    app.router.add_get("/api/approvals", get_approvals)
    app.router.add_post("/api/approvals/{id}/approve", post_approve)
    app.router.add_post("/api/approvals/{id}/deny", post_deny)
    app.router.add_get("/api/blocked", get_blocked)
    app.router.add_post("/api/blocked/{id}/unblock", post_unblock)
    app.router.add_get("/api/policy/state", get_policy_state)
    app.router.add_post("/api/policy/freeze", post_policy_freeze)
    app.router.add_post("/api/policy/resume", post_policy_resume)
    app.router.add_post("/api/policy/restrictions/off", post_policy_restrictions_off)
    app.router.add_post("/api/policy/restrictions/on", post_policy_restrictions_on)
    app.router.add_post("/api/auth/step-up/totp/enroll", post_totp_enroll)
    app.router.add_post("/api/auth/step-up/totp/verify", post_totp_verify)
    app.router.add_get("/ui/{name}", serve_ui_asset)
    app.router.add_get("/ui/fonts/{name}", serve_ui_font)
    dash_dir = Path(__file__).resolve().parent.parent / "dashboard"

    async def redirect_to_dashboard(request: web.Request) -> web.Response:
        raise web.HTTPFound("/dashboard/")

    async def serve_dashboard_style(request: web.Request) -> web.StreamResponse:
        return web.FileResponse(dash_dir / "style.css")

    async def serve_dashboard_script(request: web.Request) -> web.StreamResponse:
        return web.FileResponse(dash_dir / "app.js")

    app.router.add_get("/", redirect_to_dashboard)
    app.router.add_get("/dashboard", redirect_to_dashboard)
    app.router.add_get("/dashboard/", serve_dashboard_index)
    app.router.add_get("/favicon.ico", lambda req: web.Response(status=204))
    app.router.add_get("/style.css", serve_dashboard_style)
    app.router.add_get("/app.js", serve_dashboard_script)
    if dash_dir.is_dir():
        app.router.add_static("/dashboard/", dash_dir)
    app.router.add_post("/api/analyze", post_analyze)

    return app


def _abort_if_already_serving(port: int) -> None:
    """Exactly one harness daemon per machine.

    launchd is the sole owner. `ecosystem start-all` and a manual run are both
    possible second start vectors, and two daemons on one SQLite state dir would
    double-count threats and double-fire auto-block actions.
    """
    import httpx

    try:
        r = httpx.get(f"http://127.0.0.1:{port}/api/status", timeout=2)
        if r.status_code == 200:
            logger.error(
                "A harness daemon is already serving on port %s — exiting. "
                "launchd owns this service (com.smartindustries.cyber-harness).",
                port,
            )
            raise SystemExit(0)
    except SystemExit:
        raise
    except Exception:
        pass  # Nothing healthy there: we are the owner.


# ── Daily Summary ───────────────────────────────────────────────────

async def daily_summary_loop(db: Database, pipeline: ResponsePipeline):
    """Background task: write daily threat summary JSON every 24 hours."""
    logger.info("Daily summary scheduler started")
    while True:
        try:
            threats = db.get_threats(limit=500)
            threat_dicts = [t.model_dump(mode="json") for t in threats]
            write_threat_json(threat_dicts)
        except Exception as e:
            logger.error("Daily summary error: %s", e)

        await asyncio.sleep(86400)  # 24 hours


# ── Main Daemon ─────────────────────────────────────────────────────

async def run_daemon():
    """Main daemon entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # 1. Load config
    config = load_config()
    logger.info("AegisSIEM daemon starting with config from %s", CONFIG_PATH)

    # 2. Ensure Ollama
    ensure_ollama(config)

    # 3. Initialize components
    db_path = config.get("db_path", str(Path.home() / ".aegissiem-daemon" / "aegissiem.db"))
    db = Database(db_path)

    engine = DetectionEngine(db)
    honeypot_manager = HoneypotManager(db)

    pipeline = ResponsePipeline(
        db=db,
        honeypot_manager=honeypot_manager,
        router_host=config.get("router_host"),
        router_user=config.get("router_user", "admin"),
        router_key=config.get("router_key"),
        slack_webhook=config.get("slack_webhook"),
        imessage_recipient=config.get("imessage_recipient"),
    )

    loop = asyncio.get_event_loop()

    # 4. Start syslog input (file watcher or UDP)
    syslog_mode = config.get("syslog_mode", "file")
    observer = None

    if syslog_mode == "file":
        syslog_path = config.get("syslog_path", "/var/log/syslog")
        handler = SyslogFileHandler(engine, pipeline, loop)
        handler.set_file(syslog_path)
        observer = Observer()
        watch_dir = str(Path(syslog_path).parent)
        observer.schedule(handler, watch_dir, recursive=False)
        observer.start()
        logger.info("Watching syslog file: %s", syslog_path)
    elif syslog_mode == "udp":
        udp_port = config.get("syslog_udp_port", 514)
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(engine, pipeline),
            local_addr=("0.0.0.0", udp_port),
        )
        logger.info("Listening for UDP syslog on port %d", udp_port)

    # 5-6. Start background tasks
    auto_block_task = asyncio.create_task(pipeline.auto_block_loop())

    # 7. Start daily summary
    summary_task = asyncio.create_task(daily_summary_loop(db, pipeline))

    # 8. Start HTTP API — env var > config.yml > default 8088
    # AEGISSIEM_PORT is current; ASUSGUARD_PORT kept as a legacy fallback.
    api_port = int(
        os.environ.get("AEGISSIEM_PORT")
        or os.environ.get("ASUSGUARD_PORT")
        or config.get("api_port", 8088)
    )
    _abort_if_already_serving(api_port)
    app = create_api(db, pipeline)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", api_port)
    await site.start()
    logger.info("HTTP API listening on port %d", api_port)

    # 8b. Start ecosystem HubRuntime bridge (non-fatal standalone fallback)
    try:
        from .ecosystem_bridge import start_daemon_hub

        await start_daemon_hub(api_port)
    except Exception as exc:
        logger.warning("Ecosystem HubRuntime not started (standalone mode): %s", exc)

    # Handle shutdown
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    logger.info("AegisSIEM daemon running. Press Ctrl+C to stop.")
    await stop_event.wait()

    # Cleanup
    logger.info("Shutting down...")
    try:
        from .ecosystem_bridge import stop_daemon_hub

        await stop_daemon_hub()
    except Exception:
        pass
    auto_block_task.cancel()
    summary_task.cancel()

    if observer:
        observer.stop()
        observer.join()

    await runner.cleanup()
    await honeypot_manager.stop_all()
    db.close()
    logger.info("AegisSIEM daemon stopped.")


def main():
    """CLI entry point."""
    asyncio.run(run_daemon())


if __name__ == "__main__":
    main()
