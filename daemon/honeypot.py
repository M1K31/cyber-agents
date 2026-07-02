"""AegisSIEM Daemon - SSH, HTTP, and Telnet honeypot listeners."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from .db import Database
from .models import EscalationLevel, HoneypotEvent

logger = logging.getLogger(__name__)


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

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port
        )
        logger.info("Honeypot %s listening on port %d (tarpit=%s)", self.service, self.port, self.tarpit)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Honeypot %s stopped on port %d", self.service, self.port)

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
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

    async def stop_all(self):
        for listener in self._listeners:
            await listener.stop()
        self._listeners = []
