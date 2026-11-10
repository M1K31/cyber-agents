"""AegisSIEM Daemon - SSH, HTTP, and Telnet honeypot listeners."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from .db import Database
from .models import EscalationLevel, HoneypotEvent

logger = logging.getLogger(__name__)

# Upper bound on waiting for a listener's open connections when stopping it.
STOP_WAIT_SECONDS = 5.0


class BaseListener:
    """Base class for honeypot listeners."""

    service: str = "base"
    port: int = 0

    def __init__(self, db: Database, port: int = 0, tarpit: bool = False):
        self.db = db
        if port:
            self.port = port
        self.tarpit = tarpit
        self._server: Optional[asyncio.AbstractServer] = None
        # Handler tasks for connections currently open, so stop() can drop them.
        self._client_tasks: set[asyncio.Task] = set()

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port
        )
        logger.info("Honeypot %s listening on port %d (tarpit=%s)", self.service, self.port, self.tarpit)

    async def stop(self):
        """Stop listening and drop every open connection.

        Raises RuntimeError if a connection is still open afterwards, so the
        caller keeps treating this listener as running.
        """
        server = self._server
        if not server:
            return
        server.close()  # stop accepting; from here no new attacker can connect
        try:
            # Since Python 3.12 wait_closed() also waits for every open
            # connection. A tarpitted client that never hangs up would otherwise
            # block teardown — and anything awaiting it — indefinitely.
            await asyncio.wait_for(server.wait_closed(), timeout=STOP_WAIT_SECONDS)
        except asyncio.TimeoutError:
            # Drop the held connections ourselves (Server.abort_clients only
            # exists on 3.13+): cancelling a handler runs its finally block,
            # which closes the writer.
            clients = set(self._client_tasks)
            for task in clients:
                task.cancel()
            abort = getattr(server, "abort_clients", None)
            if callable(abort):
                abort()
            if clients:
                _, pending = await asyncio.wait(clients, timeout=STOP_WAIT_SECONDS)
                if pending:
                    raise RuntimeError(
                        f"honeypot {self.service} on port {self.port}: "
                        f"{len(pending)} connection(s) could not be closed"
                    )
            logger.warning(
                "Honeypot %s on port %d: dropped %d connection(s) still open after %.0fs",
                self.service, self.port, len(clients), STOP_WAIT_SECONDS,
            )
        self._server = None
        logger.info("Honeypot %s stopped on port %d", self.service, self.port)

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        peer = writer.get_extra_info("peername")
        attacker_ip = peer[0] if peer else "unknown"
        logger.info("Honeypot %s connection from %s", self.service, attacker_ip)
        try:
            await self._interact(reader, writer, attacker_ip)
        except (ConnectionResetError, asyncio.CancelledError, BrokenPipeError):
            pass
        except Exception:
            logger.exception("Honeypot %s error handling %s", self.service, attacker_ip)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if task is not None:
                self._client_tasks.discard(task)

    async def _interact(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, attacker_ip: str):
        raise NotImplementedError

    def _record_event(self, attacker_ip: str, event_type: str, payload: Optional[str] = None):
        profile = self.db.get_profile_by_ip(attacker_ip)
        profile_id = profile.id if profile else None
        event = HoneypotEvent(
            timestamp=datetime.utcnow(),
            attacker_ip=attacker_ip,
            port=self.port,
            service=self.service,
            event_type=event_type,
            payload=payload,
            profile_id=profile_id,
        )
        self.db.insert_honeypot_event(event)


class SSHListener(BaseListener):
    """Fake SSH server that captures connection attempts and optionally tarpits."""

    service = "ssh"
    port = 2222

    BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

    async def _interact(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, attacker_ip: str):
        self._record_event(attacker_ip, "connection")

        if self.tarpit:
            # Tarpit mode: send banner byte-by-byte with 1s delays
            for byte in self.BANNER:
                writer.write(bytes([byte]))
                await writer.drain()
                await asyncio.sleep(1)
        else:
            writer.write(self.BANNER)
            await writer.drain()

        # Read client banner
        try:
            client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            if client_banner:
                self._record_event(attacker_ip, "client_banner", client_banner.decode(errors="replace").strip())
        except asyncio.TimeoutError:
            pass

        # Keep connection open in tarpit mode
        if self.tarpit:
            try:
                while True:
                    await asyncio.sleep(10)
                    writer.write(b"\x00")
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass


class HTTPListener(BaseListener):
    """Fake ASUS router login page that captures POST credentials."""

    service = "http"
    port = 8080

    LOGIN_PAGE = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><head><title>ASUS Router</title></head><body>"
        "<h1>ASUS RT-AX88U</h1>"
        '<form method="POST" action="/login.cgi">'
        '<input name="login_username" placeholder="Username"><br>'
        '<input name="login_passwd" type="password" placeholder="Password"><br>'
        '<button type="submit">Login</button>'
        "</form></body></html>\r\n"
    )

    LOGIN_RESPONSE = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><body><h1>Login failed</h1></body></html>\r\n"
    )

    async def _interact(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, attacker_ip: str):
        self._record_event(attacker_ip, "connection")

        try:
            request_data = await asyncio.wait_for(reader.read(4096), timeout=30)
        except asyncio.TimeoutError:
            return

        request_text = request_data.decode(errors="replace")

        if request_text.startswith("POST"):
            # Extract body (after double newline)
            parts = request_text.split("\r\n\r\n", 1)
            body = parts[1] if len(parts) > 1 else ""
            self._record_event(attacker_ip, "credentials", body)
            writer.write(self.LOGIN_RESPONSE.encode())
        else:
            self._record_event(attacker_ip, "http_request", request_text[:500])
            writer.write(self.LOGIN_PAGE.encode())

        await writer.drain()


class TelnetListener(BaseListener):
    """Fake telnet server with login prompts and optional fake shell tarpit."""

    service = "telnet"
    port = 2323

    async def _interact(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, attacker_ip: str):
        self._record_event(attacker_ip, "connection")

        # Login prompt
        writer.write(b"\r\nASUS RT-AX88U login: ")
        await writer.drain()

        try:
            username = await asyncio.wait_for(reader.readline(), timeout=30)
            username_str = username.decode(errors="replace").strip()
        except asyncio.TimeoutError:
            return

        writer.write(b"Password: ")
        await writer.drain()

        try:
            password = await asyncio.wait_for(reader.readline(), timeout=30)
            password_str = password.decode(errors="replace").strip()
        except asyncio.TimeoutError:
            return

        self._record_event(attacker_ip, "credentials", f"{username_str}:{password_str}")

        if self.tarpit:
            # Fake shell mode - keep attacker engaged
            writer.write(b"\r\nWelcome to ASUS RT-AX88U.\r\n")
            writer.write(b"admin@RT-AX88U:/tmp/home/root# ")
            await writer.drain()

            try:
                while True:
                    cmd = await asyncio.wait_for(reader.readline(), timeout=120)
                    cmd_str = cmd.decode(errors="replace").strip()
                    if not cmd_str:
                        continue
                    self._record_event(attacker_ip, "command", cmd_str)
                    # Fake responses
                    if cmd_str in ("exit", "quit", "logout"):
                        break
                    writer.write(f"-sh: {cmd_str.split()[0]}: not found\r\n".encode())
                    writer.write(b"admin@RT-AX88U:/tmp/home/root# ")
                    await writer.drain()
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
                pass
        else:
            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()


class HoneypotManager:
    """Manages honeypot listener deployment based on escalation level."""

    def __init__(self, db: Database):
        self.db = db
        self._listeners: list[BaseListener] = []

    async def deploy_for_level(self, level: EscalationLevel):
        """Deploy honeypots appropriate for the given escalation level."""
        await self.stop_all()

        if level.value >= EscalationLevel.ALERT.value:
            tarpit = level.value >= EscalationLevel.CONTAIN.value
            listeners = [
                SSHListener(self.db, tarpit=tarpit),
                HTTPListener(self.db, tarpit=False),
                TelnetListener(self.db, tarpit=tarpit),
            ]
            for listener in listeners:
                try:
                    await listener.start()
                    self._listeners.append(listener)
                except OSError as e:
                    logger.warning("Could not start %s honeypot: %s", listener.service, e)

    async def stop_all(self) -> int:
        """Stop every listener; return how many could NOT be stopped.

        One listener failing must not leave the ones after it running, so every
        listener is attempted. Listeners that failed stay in ``_listeners`` — they
        are still this manager's to stop — and a later call retries them. Never
        raises: callers run this during error handling and shutdown.
        """
        still_running: list[BaseListener] = []
        for listener in self._listeners:
            try:
                await listener.stop()
            except Exception as exc:
                logger.error("Could not stop %s honeypot: %r", getattr(listener, "service", "?"), exc)
                still_running.append(listener)
        self._listeners = still_running
        return len(still_running)
