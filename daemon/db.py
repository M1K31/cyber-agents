"""AegisSIEM Daemon - SQLite database for threats, profiles, honeypot events, and approvals."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import (
    Approval,
    AttackerProfile,
    BlockedIP,
    EscalationLevel,
    HoneypotEvent,
    LogEvent,
    Severity,
    ThreatEvent,
    ThreatStatus,
)

DEFAULT_DB_PATH = Path.home() / ".aegissiem-daemon" / "aegissiem.db"
LOG_RING_SIZE = 10_000


class Database:
    """SQLite-backed storage for AegisSIEM daemon state."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()

    def _init_tables(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                router_name TEXT DEFAULT '',
                threat_type TEXT DEFAULT '',
                source_ip TEXT,
                severity TEXT DEFAULT 'LOW',
                raw_log TEXT DEFAULT '',
                status TEXT DEFAULT 'open',
                auto_block_at TEXT
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                router_name TEXT DEFAULT '',
                blocked_at TEXT NOT NULL,
                blocked_by TEXT DEFAULT 'auto',
                unblocked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                event_type TEXT DEFAULT 'OTHER',
                source_ip TEXT,
                mac_address TEXT,
                raw_line TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS attacker_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                total_attempts INTEGER DEFAULT 0,
                escalation_level INTEGER DEFAULT 0,
                asn TEXT,
                asn_org TEXT,
                country TEXT,
                city TEXT,
                reverse_dns TEXT,
                whois_org TEXT,
                whois_netblock TEXT,
                subnet_24 TEXT,
                related_profile_ids TEXT DEFAULT '[]',
                credentials_tried TEXT DEFAULT '[]',
                tools_detected TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}',
                llm_summary TEXT,
                llm_updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS honeypot_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attacker_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT,
                profile_id INTEGER
            );

            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                summary TEXT,
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
            CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip);
            CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip);
            CREATE INDEX IF NOT EXISTS idx_profiles_ip ON attacker_profiles(ip);
            CREATE INDEX IF NOT EXISTS idx_profiles_subnet ON attacker_profiles(subnet_24);
            CREATE INDEX IF NOT EXISTS idx_honeypot_ip ON honeypot_events(attacker_ip);
            CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
        """)
        self.conn.commit()

    # ── Log Events ──────────────────────────────────────────────────

    def insert_log_event(self, event: LogEvent) -> int:
        cur = self.conn.execute(
            """INSERT INTO log_events (timestamp, source, message, event_type, source_ip, mac_address, raw_line)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                event.timestamp.isoformat(),
                event.source,
                event.message,
                event.event_type.value,
                event.source_ip,
                event.mac_address,
                event.raw_line,
            ),
        )
        self.conn.commit()
        self._trim_log_ring()
        return cur.lastrowid  # type: ignore[return-value]

    def _trim_log_ring(self):
        count = self.conn.execute("SELECT COUNT(*) FROM log_events").fetchone()[0]
        if count > LOG_RING_SIZE:
            excess = count - LOG_RING_SIZE
            self.conn.execute(
                "DELETE FROM log_events WHERE id IN (SELECT id FROM log_events ORDER BY id ASC LIMIT ?)",
                (excess,),
            )
            self.conn.commit()

    def get_recent_log_events(self, limit: int = 100) -> list[LogEvent]:
        rows = self.conn.execute(
            "SELECT * FROM log_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_log_event(r) for r in rows]

    def _row_to_log_event(self, row: sqlite3.Row) -> LogEvent:
        return LogEvent(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source=row["source"],
            message=row["message"],
            event_type=row["event_type"],
            source_ip=row["source_ip"],
            mac_address=row["mac_address"],
            raw_line=row["raw_line"],
        )

    # ── Threats ─────────────────────────────────────────────────────

    def insert_threat(self, threat: ThreatEvent) -> int:
        cur = self.conn.execute(
            """INSERT INTO threats (timestamp, router_name, threat_type, source_ip, severity, raw_log, status, auto_block_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                threat.timestamp.isoformat(),
                threat.router_name,
                threat.threat_type,
                threat.source_ip,
                threat.severity.value,
                threat.raw_log,
                threat.status.value,
                threat.auto_block_at.isoformat() if threat.auto_block_at else None,
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_threat(self, threat_id: int) -> Optional[ThreatEvent]:
        row = self.conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
        return self._row_to_threat(row) if row else None

    def get_threats(self, status: Optional[str] = None, limit: int = 100) -> list[ThreatEvent]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM threats WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_threat(r) for r in rows]

    def get_threats_aggregated(self) -> dict:
        """Return threat counts grouped by status and severity."""
        by_status = {}
        for row in self.conn.execute("SELECT status, COUNT(*) as cnt FROM threats GROUP BY status").fetchall():
            by_status[row["status"]] = row["cnt"]
        by_severity = {}
        for row in self.conn.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity").fetchall():
            by_severity[row["severity"]] = row["cnt"]
        return {"by_status": by_status, "by_severity": by_severity}

    def get_open_threats_past_deadline(self) -> list[ThreatEvent]:
        now = datetime.utcnow().isoformat()
        rows = self.conn.execute(
            "SELECT * FROM threats WHERE status = 'open' AND auto_block_at IS NOT NULL AND auto_block_at <= ?",
            (now,),
        ).fetchall()
        return [self._row_to_threat(r) for r in rows]

    def update_threat_status(self, threat_id: int, status: ThreatStatus):
        self.conn.execute(
            "UPDATE threats SET status = ? WHERE id = ?",
            (status.value, threat_id),
        )
        self.conn.commit()

    def _row_to_threat(self, row: sqlite3.Row) -> ThreatEvent:
        return ThreatEvent(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            router_name=row["router_name"],
            threat_type=row["threat_type"],
            source_ip=row["source_ip"],
            severity=Severity(row["severity"]),
            raw_log=row["raw_log"],
            status=ThreatStatus(row["status"]),
            auto_block_at=datetime.fromisoformat(row["auto_block_at"]) if row["auto_block_at"] else None,
        )

    # ── Blocked IPs ─────────────────────────────────────────────────

    def insert_blocked_ip(self, blocked: BlockedIP) -> int:
        cur = self.conn.execute(
            """INSERT INTO blocked_ips (ip, router_name, blocked_at, blocked_by, unblocked_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                blocked.ip,
                blocked.router_name,
                blocked.blocked_at.isoformat(),
                blocked.blocked_by,
                blocked.unblocked_at.isoformat() if blocked.unblocked_at else None,
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_blocked_ips(self, active_only: bool = True) -> list[BlockedIP]:
        if active_only:
            rows = self.conn.execute(
                "SELECT * FROM blocked_ips WHERE unblocked_at IS NULL ORDER BY id DESC"
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM blocked_ips ORDER BY id DESC").fetchall()
        return [self._row_to_blocked(r) for r in rows]

    def unblock_ip(self, ip: str):
        self.conn.execute(
            "UPDATE blocked_ips SET unblocked_at = ? WHERE ip = ? AND unblocked_at IS NULL",
            (datetime.utcnow().isoformat(), ip),
        )
        self.conn.commit()

    def _row_to_blocked(self, row: sqlite3.Row) -> BlockedIP:
        return BlockedIP(
            id=row["id"],
            ip=row["ip"],
            router_name=row["router_name"],
            blocked_at=datetime.fromisoformat(row["blocked_at"]),
            blocked_by=row["blocked_by"],
            unblocked_at=datetime.fromisoformat(row["unblocked_at"]) if row["unblocked_at"] else None,
        )

    # ── Attacker Profiles ───────────────────────────────────────────

    def upsert_profile(self, profile: AttackerProfile) -> int:
        existing = self.get_profile_by_ip(profile.ip)
        if existing:
            self.conn.execute(
                """UPDATE attacker_profiles SET
                    last_seen = ?, total_attempts = ?, escalation_level = ?,
                    asn = COALESCE(?, asn), asn_org = COALESCE(?, asn_org),
                    country = COALESCE(?, country), city = COALESCE(?, city),
                    reverse_dns = COALESCE(?, reverse_dns),
                    whois_org = COALESCE(?, whois_org), whois_netblock = COALESCE(?, whois_netblock),
                    subnet_24 = ?, related_profile_ids = ?,
                    credentials_tried = ?, tools_detected = ?,
                    metadata = ?, llm_summary = COALESCE(?, llm_summary),
                    llm_updated_at = COALESCE(?, llm_updated_at)
                WHERE ip = ?""",
                (
                    profile.last_seen.isoformat(),
                    profile.total_attempts,
                    profile.escalation_level.value,
                    profile.asn,
                    profile.asn_org,
                    profile.country,
                    profile.city,
                    profile.reverse_dns,
                    profile.whois_org,
                    profile.whois_netblock,
                    profile.subnet_24,
                    json.dumps(profile.related_profile_ids),
                    json.dumps(profile.credentials_tried),
                    json.dumps(profile.tools_detected),
                    json.dumps(profile.metadata),
                    profile.llm_summary,
                    profile.llm_updated_at.isoformat() if profile.llm_updated_at else None,
                    profile.ip,
                ),
            )
            self.conn.commit()
            return existing.id  # type: ignore[return-value]
        else:
            cur = self.conn.execute(
                """INSERT INTO attacker_profiles
                   (ip, first_seen, last_seen, total_attempts, escalation_level,
                    asn, asn_org, country, city, reverse_dns, whois_org, whois_netblock,
                    subnet_24, related_profile_ids, credentials_tried, tools_detected,
                    metadata, llm_summary, llm_updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    profile.ip,
                    profile.first_seen.isoformat(),
                    profile.last_seen.isoformat(),
                    profile.total_attempts,
                    profile.escalation_level.value,
                    profile.asn,
                    profile.asn_org,
                    profile.country,
                    profile.city,
                    profile.reverse_dns,
                    profile.whois_org,
                    profile.whois_netblock,
                    profile.subnet_24,
                    json.dumps(profile.related_profile_ids),
                    json.dumps(profile.credentials_tried),
                    json.dumps(profile.tools_detected),
                    json.dumps(profile.metadata),
                    profile.llm_summary,
                    profile.llm_updated_at.isoformat() if profile.llm_updated_at else None,
                ),
            )
            self.conn.commit()
            return cur.lastrowid  # type: ignore[return-value]

    def get_profile_by_ip(self, ip: str) -> Optional[AttackerProfile]:
        row = self.conn.execute("SELECT * FROM attacker_profiles WHERE ip = ?", (ip,)).fetchone()
        return self._row_to_profile(row) if row else None

    def get_profiles(self, limit: int = 100) -> list[AttackerProfile]:
        rows = self.conn.execute(
            "SELECT * FROM attacker_profiles ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_profile(r) for r in rows]

    def get_profiles_by_subnet(self, subnet_24: str) -> list[AttackerProfile]:
        rows = self.conn.execute(
            "SELECT * FROM attacker_profiles WHERE subnet_24 = ?", (subnet_24,)
        ).fetchall()
        return [self._row_to_profile(r) for r in rows]

    def _row_to_profile(self, row: sqlite3.Row) -> AttackerProfile:
        return AttackerProfile(
            id=row["id"],
            ip=row["ip"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            total_attempts=row["total_attempts"],
            escalation_level=EscalationLevel(row["escalation_level"]),
            asn=row["asn"],
            asn_org=row["asn_org"],
            country=row["country"],
            city=row["city"],
            reverse_dns=row["reverse_dns"],
            whois_org=row["whois_org"],
            whois_netblock=row["whois_netblock"],
            subnet_24=row["subnet_24"],
            related_profile_ids=json.loads(row["related_profile_ids"] or "[]"),
            credentials_tried=json.loads(row["credentials_tried"] or "[]"),
            tools_detected=json.loads(row["tools_detected"] or "[]"),
            metadata=json.loads(row["metadata"] or "{}"),
            llm_summary=row["llm_summary"],
            llm_updated_at=datetime.fromisoformat(row["llm_updated_at"]) if row["llm_updated_at"] else None,
        )

    # ── Honeypot Events ─────────────────────────────────────────────

    def insert_honeypot_event(self, event: HoneypotEvent) -> int:
        cur = self.conn.execute(
            """INSERT INTO honeypot_events (timestamp, attacker_ip, port, service, event_type, payload, profile_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                event.timestamp.isoformat(),
                event.attacker_ip,
                event.port,
                event.service,
                event.event_type,
                event.payload,
                event.profile_id,
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_honeypot_events(self, limit: int = 100) -> list[HoneypotEvent]:
        rows = self.conn.execute(
            "SELECT * FROM honeypot_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_honeypot(r) for r in rows]

    def _row_to_honeypot(self, row: sqlite3.Row) -> HoneypotEvent:
        return HoneypotEvent(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            attacker_ip=row["attacker_ip"],
            port=row["port"],
            service=row["service"],
            event_type=row["event_type"],
            payload=row["payload"],
            profile_id=row["profile_id"],
        )

    # ── Approvals ───────────────────────────────────────────────────

    def insert_approval(self, approval: Approval) -> int:
        cur = self.conn.execute(
            """INSERT INTO approvals (profile_id, action, status, summary, created_at, resolved_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                approval.profile_id,
                approval.action,
                approval.status,
                approval.summary,
                approval.created_at.isoformat(),
                approval.resolved_at.isoformat() if approval.resolved_at else None,
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_approval(self, approval_id: int) -> Optional[Approval]:
        row = self.conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return self._row_to_approval(row) if row else None

    def get_pending_approvals(self) -> list[Approval]:
        rows = self.conn.execute(
            "SELECT * FROM approvals WHERE status = 'pending' ORDER BY id DESC"
        ).fetchall()
        return [self._row_to_approval(r) for r in rows]

    def update_approval(self, approval_id: int, status: str):
        self.conn.execute(
            "UPDATE approvals SET status = ?, resolved_at = ? WHERE id = ?",
            (status, datetime.utcnow().isoformat(), approval_id),
        )
        self.conn.commit()

    def _row_to_approval(self, row: sqlite3.Row) -> Approval:
        return Approval(
            id=row["id"],
            profile_id=row["profile_id"],
            action=row["action"],
            status=row["status"],
            summary=row["summary"],
            created_at=datetime.fromisoformat(row["created_at"]),
            resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
        )

    def close(self):
        self.conn.close()
