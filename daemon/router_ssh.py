"""AegisSIEM Daemon - SSH-based iptables management for ASUS routers via asyncssh."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import asyncssh

logger = logging.getLogger(__name__)


async def _ssh_connect(
    host: str,
    username: str = "admin",
    key_file: Optional[str] = None,
    port: int = 22,
) -> asyncssh.SSHClientConnection:
    """Create an SSH connection to the router."""
    opts: dict = {
        "host": host,
        "username": username,
        "port": port,
        "known_hosts": None,  # Skip host key verification for router
    }
    if key_file:
        opts["client_keys"] = [str(Path(key_file).expanduser())]
    return await asyncssh.connect(**opts)


async def _run_command(
    host: str,
    command: str,
    username: str = "admin",
    key_file: Optional[str] = None,
    port: int = 22,
    retries: int = 1,
) -> tuple[bool, str]:
    """Run a command on the router via SSH with retry.

    Returns:
        (success, output_or_error)
    """
    for attempt in range(retries + 1):
        try:
            async with await _ssh_connect(host, username, key_file, port) as conn:
                result = await conn.run(command, check=False)
                output = (result.stdout or "") + (result.stderr or "")
                if result.exit_status == 0:
                    return True, output.strip()
                else:
                    logger.warning(
                        "Command failed (attempt %d/%d) on %s: %s -> %s",
                        attempt + 1, retries + 1, host, command, output.strip(),
                    )
        except (asyncssh.Error, OSError) as e:
            logger.warning(
                "SSH error (attempt %d/%d) connecting to %s: %s",
                attempt + 1, retries + 1, host, e,
            )
            if attempt == retries:
                return False, str(e)

    return False, "Max retries exceeded"


async def block_ip(
    ip: str,
    host: str,
    username: str = "admin",
    key_file: Optional[str] = None,
    port: int = 22,
) -> bool:
    """Block an IP on the router using iptables INPUT and FORWARD rules.

    Args:
        ip: IP address to block.
        host: Router hostname or IP.
        username: SSH username.
        key_file: Path to SSH private key.
        port: SSH port.

    Returns:
        True if both rules were applied successfully.
    """
    cmd_input = f"iptables -I INPUT -s {ip} -j DROP"
    cmd_forward = f"iptables -I FORWARD -s {ip} -j DROP"

    success_input, out1 = await _run_command(host, cmd_input, username, key_file, port)
    success_forward, out2 = await _run_command(host, cmd_forward, username, key_file, port)

    if success_input and success_forward:
        logger.info("Blocked IP %s on %s", ip, host)
        return True
    else:
        logger.error("Failed to fully block IP %s on %s: INPUT=%s FORWARD=%s", ip, host, out1, out2)
        return False


async def unblock_ip(
    ip: str,
    host: str,
    username: str = "admin",
    key_file: Optional[str] = None,
    port: int = 22,
) -> bool:
    """Remove iptables block rules for an IP.

    Uses 2>/dev/null to suppress errors if rules don't exist.
    """
    cmd_input = f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null"
    cmd_forward = f"iptables -D FORWARD -s {ip} -j DROP 2>/dev/null"

    success1, _ = await _run_command(host, cmd_input, username, key_file, port)
    success2, _ = await _run_command(host, cmd_forward, username, key_file, port)

    logger.info("Unblocked IP %s on %s (INPUT=%s, FORWARD=%s)", ip, host, success1, success2)
    return True  # Best-effort unblock


async def reapply_blocks(
    blocked_ips: list[str],
    host: str,
    username: str = "admin",
    key_file: Optional[str] = None,
    port: int = 22,
) -> int:
    """Re-apply all block rules (e.g., after router reboot).

    Args:
        blocked_ips: List of IP addresses to block.
        host: Router hostname or IP.
        username: SSH username.
        key_file: Path to SSH private key.
        port: SSH port.

    Returns:
        Number of IPs successfully blocked.
    """
    success_count = 0
    for ip in blocked_ips:
        if await block_ip(ip, host, username, key_file, port):
            success_count += 1

    logger.info("Reapplied blocks: %d/%d successful on %s", success_count, len(blocked_ips), host)
    return success_count
