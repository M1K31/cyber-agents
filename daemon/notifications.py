"""AegisSIEM Daemon - Notification delivery: Slack webhook and iMessage."""

from __future__ import annotations

import logging
import platform
import subprocess
from typing import Optional

import httpx

from .models import Severity, ThreatEvent

logger = logging.getLogger(__name__)


def format_threat_message(threat: ThreatEvent) -> str:
    """Format a threat event into a human-readable notification message."""
    severity_emoji = {
        Severity.LOW: "[LOW]",
        Severity.MEDIUM: "[MEDIUM]",
        Severity.HIGH: "[HIGH]",
        Severity.CRITICAL: "[CRITICAL]",
    }
    prefix = severity_emoji.get(threat.severity, "[?]")
    lines = [
        f"{prefix} AegisSIEM Threat Detected",
        f"Type: {threat.threat_type}",
        f"Source IP: {threat.source_ip or 'N/A'}",
        f"Router: {threat.router_name or 'N/A'}",
        f"Time: {threat.timestamp.isoformat()}",
        f"Status: {threat.status.value}",
    ]
    if threat.auto_block_at:
        lines.append(f"Auto-block at: {threat.auto_block_at.isoformat()}")
    if threat.raw_log:
        lines.append(f"Log: {threat.raw_log[:200]}")
    return "\n".join(lines)


def send_slack_sync(webhook_url: str, message: str) -> bool:
    """Send a message to Slack via webhook (synchronous).

    Args:
        webhook_url: Slack incoming webhook URL.
        message: Message text to send.

    Returns:
        True if the message was sent successfully.
    """
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(webhook_url, json={"text": message})
            if resp.status_code == 200:
                logger.info("Slack notification sent")
                return True
            else:
                logger.warning("Slack webhook returned %d: %s", resp.status_code, resp.text)
                return False
    except httpx.HTTPError as e:
        logger.error("Slack notification failed: %s", e)
        return False


def send_imessage(recipient: str, message: str) -> bool:
    """Send an iMessage via osascript (macOS only).

    Args:
        recipient: Phone number or email for iMessage.
        message: Message text to send.

    Returns:
        True if the message was sent successfully.
    """
    if platform.system() != "Darwin":
        logger.warning("iMessage is only available on macOS")
        return False

    # Sanitize message for AppleScript - escape backslashes and quotes
    safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
    safe_recipient = recipient.replace("\\", "\\\\").replace('"', '\\"')

    script = (
        f'tell application "Messages"\n'
        f'  set targetService to 1st account whose service type = iMessage\n'
        f'  set targetBuddy to participant "{safe_recipient}" of targetService\n'
        f'  send "{safe_message}" to targetBuddy\n'
        f'end tell'
    )

    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            logger.info("iMessage sent to %s", recipient)
            return True
        else:
            logger.warning("iMessage failed: %s", result.stderr)
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.error("iMessage error: %s", e)
        return False


def notify(
    threat: ThreatEvent,
    slack_webhook: Optional[str] = None,
    imessage_recipient: Optional[str] = None,
) -> list[str]:
    """Dispatch notifications to all configured channels.

    Args:
        threat: The threat event to notify about.
        slack_webhook: Slack webhook URL (optional).
        imessage_recipient: iMessage recipient (optional).

    Returns:
        List of channels that were successfully notified.
    """
    message = format_threat_message(threat)
    notified: list[str] = []

    if slack_webhook:
        if send_slack_sync(slack_webhook, message):
            notified.append("slack")

    if imessage_recipient:
        if send_imessage(imessage_recipient, message):
            notified.append("imessage")

    if not notified:
        logger.info("No notification channels configured or all failed")

    return notified
