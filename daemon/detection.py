"""AegisSIEM Daemon - Consolidated detection engine for brute force, deauth, and DNS rebind attacks."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from .db import Database
from .models import (
    AttackerProfile,
    EscalationLevel,
    EventType,
    LogEvent,
    Severity,
    ThreatEvent,
)

logger = logging.getLogger(__name__)


# ── Escalation Logic ────────────────────────────────────────────────

def compute_escalation(total_attempts: int, current_level: EscalationLevel) -> EscalationLevel:
    """Compute the escalation level based on attempt count. Never de-escalates."""
    if total_attempts >= 50:
        target = EscalationLevel.INVESTIGATE
    elif total_attempts >= 20:
        target = EscalationLevel.PROFILED
    elif total_attempts >= 10:
        target = EscalationLevel.CONTAIN
    elif total_attempts >= 5:
        target = EscalationLevel.ALERT
    else:
        target = EscalationLevel.OBSERVE

    # Never de-escalate
    if target.value > current_level.value:
        return target
    return current_level


def escalate_profile(db: Database, ip: str, total_attempts: int) -> Optional[AttackerProfile]:
    """Update a profile's escalation level based on cumulative attempts."""
    profile = db.get_profile_by_ip(ip)
    if not profile:
        return None

    new_level = compute_escalation(total_attempts, profile.escalation_level)
    if new_level != profile.escalation_level:
        profile.escalation_level = new_level
        profile.total_attempts = total_attempts
        profile.last_seen = datetime.utcnow()
        db.upsert_profile(profile)
        logger.info("Escalated %s to %s (attempts=%d)", ip, new_level.name, total_attempts)

    return profile


def check_escalation(db: Database, ip: str) -> Optional[EscalationLevel]:
    """Check and propagate escalation to /24 subnet peers."""
    profile = db.get_profile_by_ip(ip)
    if not profile or not profile.subnet_24:
        return profile.escalation_level if profile else None

    peers = db.get_profiles_by_subnet(profile.subnet_24)
    for peer in peers:
        if peer.ip == ip:
            continue
        peer_level = compute_escalation(peer.total_attempts, peer.escalation_level)
        # Propagate: if main profile is at CONTAIN or above, raise peers to at least ALERT
        if profile.escalation_level.value >= EscalationLevel.CONTAIN.value:
            if peer_level.value < EscalationLevel.ALERT.value:
                peer.escalation_level = EscalationLevel.ALERT
                db.upsert_profile(peer)
                logger.info("Propagated ALERT to subnet peer %s", peer.ip)

    return profile.escalation_level


# ── Brute Force Detector ───────────────────────────────────────────

class BruteForceDetector:
    """Detects brute force login attempts using sliding windows."""

    def __init__(
        self,
        max_failures: int = 5,
        window: int = 3600,
        slow_threshold: int = 10,
        auto_block_delay: int = 10800,
    ):
        self.max_failures = max_failures
        self.window = window  # seconds
        self.slow_threshold = slow_threshold
        self.auto_block_delay = auto_block_delay  # seconds
        self._failures: dict[str, list[datetime]] = {}
        self._total_failures: dict[str, int] = {}
        self._alerted: set[str] = set()

    def _prune(self, ip: str, now: datetime):
        cutoff = now - timedelta(seconds=self.window)
        self._failures[ip] = [t for t in self._failures.get(ip, []) if t > cutoff]

    def process(self, event: LogEvent) -> Optional[ThreatEvent]:
        ip = event.source_ip
        if not ip:
            return None

        now = event.timestamp

        if event.event_type == EventType.LOGIN_SUCCESS:
            # Success from a previously-failed IP = brute force success
            if ip in self._failures and self._failures[ip]:
                self._failures.pop(ip, None)
                self._total_failures.pop(ip, None)
                self._alerted.discard(ip)
                return ThreatEvent(
                    timestamp=now,
                    router_name=event.source,
                    threat_type="brute_force_success",
                    source_ip=ip,
                    severity=Severity.CRITICAL,
                    raw_log=event.raw_line,
                    auto_block_at=now,  # Immediate
                )
            return None

        if event.event_type not in (EventType.LOGIN_FAIL, EventType.CAPTCHA_ERROR):
            return None

        # Track failure
        self._failures.setdefault(ip, []).append(now)
        self._total_failures[ip] = self._total_failures.get(ip, 0) + 1
        self._prune(ip, now)

        burst_count = len(self._failures[ip])
        total = self._total_failures[ip]

        # Burst detection: N failures within window
        if burst_count >= self.max_failures and ip not in self._alerted:
            self._alerted.add(ip)
            return ThreatEvent(
                timestamp=now,
                router_name=event.source,
                threat_type="brute_force_burst",
                source_ip=ip,
                severity=Severity.HIGH,
                raw_log=event.raw_line,
                auto_block_at=now + timedelta(seconds=self.auto_block_delay),
            )

        # Slow brute force detection
        if total >= self.slow_threshold and f"{ip}_slow" not in self._alerted:
            self._alerted.add(f"{ip}_slow")
            return ThreatEvent(
                timestamp=now,
                router_name=event.source,
                threat_type="brute_force_slow",
                source_ip=ip,
                severity=Severity.HIGH,
                raw_log=event.raw_line,
                auto_block_at=now + timedelta(seconds=self.auto_block_delay),
            )

        return None


# ── Deauth Detector ────────────────────────────────────────────────

class DeauthDetector:
    """Detects excessive deauthentication frames (potential deauth attack)."""

    BAND_STEERING_REASONS = {"band steering", "band_steering"}

    def __init__(self, rate_threshold: int = 20, window: int = 60):
        self.rate_threshold = rate_threshold
        self.window = window  # seconds
        self._events: dict[str, list[datetime]] = {}

    def _prune(self, mac: str, now: datetime):
        cutoff = now - timedelta(seconds=self.window)
        self._events[mac] = [t for t in self._events.get(mac, []) if t > cutoff]

    def process(self, event: LogEvent) -> Optional[ThreatEvent]:
        if event.event_type != EventType.DEAUTH:
            return None

        mac = event.mac_address
        if not mac:
            return None

        # Filter band steering
        msg_lower = event.message.lower()
        for reason in self.BAND_STEERING_REASONS:
            if reason in msg_lower:
                return None

        now = event.timestamp
        self._events.setdefault(mac, []).append(now)
        self._prune(mac, now)

        if len(self._events[mac]) >= self.rate_threshold:
            self._events[mac] = []  # Reset after alert
            return ThreatEvent(
                timestamp=now,
                router_name=event.source,
                threat_type="deauth_flood",
                source_ip=None,
                severity=Severity.HIGH,
                raw_log=event.raw_line,
            )

        return None


# ── DNS Rebind Detector ────────────────────────────────────────────

class DNSRebindDetector:
    """Detects DNS rebinding attempts, filtering known benign sources."""

    WHITELIST = {"chromecast", "google", "localhost"}

    def __init__(self):
        self._seen: set[str] = set()

    def process(self, event: LogEvent) -> Optional[ThreatEvent]:
        if event.event_type != EventType.DNS_REBIND:
            return None

        msg_lower = event.message.lower()
        for safe in self.WHITELIST:
            if safe in msg_lower:
                return None

        # Deduplicate by timestamp+message
        dedup_key = f"{event.timestamp.isoformat()}:{event.message}"
        if dedup_key in self._seen:
            return None
        self._seen.add(dedup_key)

        return ThreatEvent(
            timestamp=event.timestamp,
            router_name=event.source,
            threat_type="dns_rebind",
            source_ip=event.source_ip,
            severity=Severity.MEDIUM,
            raw_log=event.raw_line,
        )


# ── Detection Engine ───────────────────────────────────────────────

class DetectionEngine:
    """Dispatches log events to all detectors and manages attacker profiles."""

    def __init__(self, db: Database):
        self.db = db
        self.brute_force = BruteForceDetector()
        self.deauth = DeauthDetector()
        self.dns_rebind = DNSRebindDetector()

    def process_event(self, event: LogEvent) -> list[ThreatEvent]:
        """Process a log event through all detectors.

        Returns list of generated threat events.
        """
        threats: list[ThreatEvent] = []

        for detector in (self.brute_force, self.deauth, self.dns_rebind):
            threat = detector.process(event)
            if threat:
                threats.append(threat)

        # Update attacker profile for events with source IPs
        if event.source_ip and event.event_type in (
            EventType.LOGIN_FAIL,
            EventType.CAPTCHA_ERROR,
            EventType.LOGIN_SUCCESS,
        ):
            self._update_profile(event)

        return threats

    def _update_profile(self, event: LogEvent):
        """Create or update an attacker profile for the given event."""
        ip = event.source_ip
        if not ip:
            return

        profile = self.db.get_profile_by_ip(ip)
        now = event.timestamp

        if profile is None:
            # Compute /24 subnet
            parts = ip.rsplit(".", 1)
            subnet_24 = f"{parts[0]}.0/24" if len(parts) == 2 else None

            profile = AttackerProfile(
                ip=ip,
                first_seen=now,
                last_seen=now,
                total_attempts=1,
                subnet_24=subnet_24,
            )
        else:
            profile.last_seen = now
            profile.total_attempts += 1

        self.db.upsert_profile(profile)

        # Check escalation
        escalate_profile(self.db, ip, profile.total_attempts)
        check_escalation(self.db, ip)
