"""AegisSIEM Daemon - Regex-based ASUS router syslog parser."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import EventType, LogEvent

# ── Regex patterns ──────────────────────────────────────────────────

LINE_RE = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+?):\s+(.*)$")

LOGIN_RE = re.compile(
    r"HTTPD:\s+\[LOGIN\]\[https?\]\[(Web|APP)\]\s+(fail|captcha error|success)\s+\((\d+\.\d+\.\d+\.\d+)\)"
)

DEAUTH_RE = re.compile(
    r"Deauth_ind\s+([0-9A-Fa-f:]{17}),\s+status:\s+(\d+),\s+reason:\s+(.+?)\s+\((\d+)\)"
)

DNS_REBIND_RE = re.compile(r"DNS rebind", re.IGNORECASE)


def classify_event(message: str) -> tuple[EventType, Optional[str], Optional[str]]:
    """Classify a syslog message and extract IP/MAC if applicable.

    Returns:
        (event_type, source_ip_or_None, mac_address_or_None)
    """
    login_match = LOGIN_RE.search(message)
    if login_match:
        outcome = login_match.group(2).lower()
        ip = login_match.group(3)
        if outcome == "fail":
            return EventType.LOGIN_FAIL, ip, None
        elif outcome == "captcha error":
            return EventType.CAPTCHA_ERROR, ip, None
        elif outcome == "success":
            return EventType.LOGIN_SUCCESS, ip, None

    deauth_match = DEAUTH_RE.search(message)
    if deauth_match:
        mac = deauth_match.group(1)
        return EventType.DEAUTH, None, mac

    if DNS_REBIND_RE.search(message):
        return EventType.DNS_REBIND, None, None

    return EventType.OTHER, None, None


def parse_line(line: str, year: Optional[int] = None) -> Optional[LogEvent]:
    """Parse a single syslog line into a LogEvent.

    Args:
        line: Raw syslog line.
        year: Year to assume (syslog timestamps lack year). Defaults to current year.

    Returns:
        LogEvent or None if the line doesn't match the expected format.
    """
    line = line.strip()
    if not line:
        return None

    m = LINE_RE.match(line)
    if not m:
        return None

    ts_str, source, message = m.group(1), m.group(2), m.group(3)

    if year is None:
        year = datetime.now().year

    try:
        timestamp = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    event_type, source_ip, mac_address = classify_event(message)

    return LogEvent(
        timestamp=timestamp,
        source=source,
        message=message,
        event_type=event_type,
        source_ip=source_ip,
        mac_address=mac_address,
        raw_line=line,
    )


def parse_file(path: Path | str, year: Optional[int] = None) -> list[LogEvent]:
    """Parse all lines from a syslog file.

    Args:
        path: Path to the syslog file.
        year: Year to assume for timestamps.

    Returns:
        List of parsed LogEvent objects (skips unparseable lines).
    """
    events: list[LogEvent] = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line, year=year)
            if event is not None:
                events.append(event)
    return events
