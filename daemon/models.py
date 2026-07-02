"""AegisSIEM Daemon - Data models for log events, threats, profiles, and honeypot."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class EventType(str, enum.Enum):
    LOGIN_FAIL = "LOGIN_FAIL"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    CAPTCHA_ERROR = "CAPTCHA_ERROR"
    DEAUTH = "DEAUTH"
    DNS_REBIND = "DNS_REBIND"
    OTHER = "OTHER"


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    blocked = "blocked"
    resolved = "resolved"


class LogEvent(BaseModel):
    timestamp: datetime
    source: str
    message: str
    event_type: EventType = EventType.OTHER
    source_ip: Optional[str] = None
    mac_address: Optional[str] = None
    raw_line: str = ""


class ThreatEvent(BaseModel):
    id: Optional[int] = None
    timestamp: datetime
    router_name: str = ""
    threat_type: str = ""
    source_ip: Optional[str] = None
    severity: Severity = Severity.LOW
    raw_log: str = ""
    status: ThreatStatus = ThreatStatus.open
    auto_block_at: Optional[datetime] = None


class BlockedIP(BaseModel):
    id: Optional[int] = None
    ip: str
    router_name: str = ""
    blocked_at: datetime = Field(default_factory=datetime.utcnow)
    blocked_by: str = "auto"
    unblocked_at: Optional[datetime] = None


class EscalationLevel(int, enum.Enum):
    OBSERVE = 0
    ALERT = 1
    CONTAIN = 2
    PROFILED = 25
    INVESTIGATE = 3


class AttackerProfile(BaseModel):
    id: Optional[int] = None
    ip: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    total_attempts: int = 0
    escalation_level: EscalationLevel = EscalationLevel.OBSERVE
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    reverse_dns: Optional[str] = None
    whois_org: Optional[str] = None
    whois_netblock: Optional[str] = None
    subnet_24: Optional[str] = None
    related_profile_ids: list[int] = Field(default_factory=list)
    credentials_tried: list[str] = Field(default_factory=list)
    tools_detected: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    llm_summary: Optional[str] = None
    llm_updated_at: Optional[datetime] = None


class HoneypotEvent(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    attacker_ip: str
    port: int
    service: str
    event_type: str
    payload: Optional[str] = None
    profile_id: Optional[int] = None


class Approval(BaseModel):
    id: Optional[int] = None
    profile_id: int
    action: str
    status: str = "pending"
    summary: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
