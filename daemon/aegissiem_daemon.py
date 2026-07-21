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
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer

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

def create_api(db: Database, pipeline: ResponsePipeline) -> web.Application:
    """Create the aiohttp web application with API routes."""
    app = web.Application()

    async def get_status(request: web.Request) -> web.Response:
        aggregated = db.get_threats_aggregated()
        blocked = db.get_blocked_ips()
        profiles = db.get_profiles(limit=0)
        return web.json_response({
            "status": "running",
            "threats": aggregated,
            "blocked_count": len(blocked),
            "profile_count": len(profiles) if isinstance(profiles, list) else 0,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def get_threats(request: web.Request) -> web.Response:
        status_filter = request.query.get("status")
        limit = int(request.query.get("limit", "100"))
        threats = db.get_threats(status=status_filter, limit=limit)
        return web.json_response([t.model_dump(mode="json") for t in threats])

    async def post_block_threat(request: web.Request) -> web.Response:
        threat_id = int(request.match_info["id"])
        success = await pipeline.block_threat(threat_id)
        if success:
            return web.json_response({"status": "blocked", "threat_id": threat_id})
        return web.json_response({"status": "failed", "threat_id": threat_id}, status=500)

    async def post_resolve_threat(request: web.Request) -> web.Response:
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

    async def post_approve(request: web.Request) -> web.Response:
        approval_id = int(request.match_info["id"])
        success = pipeline.approval_manager.approve(approval_id)
        if success:
            return web.json_response({"status": "approved", "id": approval_id})
        return web.json_response({"status": "not_found_or_not_pending"}, status=404)

    async def post_deny(request: web.Request) -> web.Response:
        approval_id = int(request.match_info["id"])
        success = pipeline.approval_manager.deny(approval_id)
        if success:
            return web.json_response({"status": "denied", "id": approval_id})
        return web.json_response({"status": "not_found_or_not_pending"}, status=404)

    async def get_blocked(request: web.Request) -> web.Response:
        blocked = db.get_blocked_ips()
        return web.json_response([b.model_dump(mode="json") for b in blocked])

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

        return web.json_response({
            "status": "ok",
            "result": text,
            "model": model,
            "source": "harness",
            "provider": provider,
        })

    app.router.add_get("/api/status", get_status)
    app.router.add_get("/api/threats", get_threats)
    app.router.add_post("/api/threats/{id}/block", post_block_threat)
    app.router.add_post("/api/threats/{id}/resolve", post_resolve_threat)
    app.router.add_get("/api/profiles", get_profiles)
    app.router.add_get("/api/honeypot/events", get_honeypot_events)
    app.router.add_post("/api/approvals/{id}/approve", post_approve)
    app.router.add_post("/api/approvals/{id}/deny", post_deny)
    app.router.add_get("/api/blocked", get_blocked)
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
