#!/usr/bin/env python3
"""AegisSIEM MCP Server — Exposes threat data and response actions to Claude Code."""

import json
import sys
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / ".aegissiem-daemon" / "aegissiem.db"
VAULT_PATH = Path(__file__).parent.parent / "vault" / "threat-data"

def get_db():
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def handle_tool_call(name, arguments):
    db = get_db()
    if not db:
        return {"error": "AegisSIEM database not found. Is the daemon running?"}

    try:
        if name == "get_threats":
            limit = arguments.get("limit", 50)
            status = arguments.get("status")
            if status:
                rows = db.execute(
                    "SELECT * FROM threats WHERE status = ? ORDER BY timestamp DESC LIMIT ?",
                    (status, limit)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

        elif name == "get_blocked_ips":
            rows = db.execute(
                "SELECT * FROM blocked_ips WHERE unblocked_at IS NULL ORDER BY blocked_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

        elif name == "get_profiles":
            limit = arguments.get("limit", 50)
            min_level = arguments.get("min_level", 0)
            rows = db.execute(
                "SELECT * FROM attacker_profiles WHERE escalation_level >= ? ORDER BY escalation_level DESC, last_seen DESC LIMIT ?",
                (min_level, limit)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                for f in ("related_profile_ids", "credentials_tried", "tools_detected", "metadata"):
                    if d.get(f):
                        d[f] = json.loads(d[f])
                results.append(d)
            return results

        elif name == "get_honeypot_events":
            limit = arguments.get("limit", 50)
            attacker_ip = arguments.get("attacker_ip")
            if attacker_ip:
                rows = db.execute(
                    "SELECT * FROM honeypot_events WHERE attacker_ip = ? ORDER BY timestamp DESC LIMIT ?",
                    (attacker_ip, limit)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM honeypot_events ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                if d.get("payload"):
                    d["payload"] = json.loads(d["payload"])
                results.append(d)
            return results

        elif name == "get_status":
            open_threats = db.execute("SELECT COUNT(*) FROM threats WHERE status = 'open'").fetchone()[0]
            blocked_count = db.execute("SELECT COUNT(*) FROM blocked_ips WHERE unblocked_at IS NULL").fetchone()[0]
            profile_count = db.execute("SELECT COUNT(*) FROM attacker_profiles WHERE escalation_level >= 1").fetchone()[0]
            honeypot_24h = db.execute(
                "SELECT COUNT(*) FROM honeypot_events WHERE timestamp >= datetime('now', '-1 day')"
            ).fetchone()[0]
            pending_approvals = db.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
            return {
                "open_threats": open_threats,
                "blocked_ips": blocked_count,
                "active_profiles": profile_count,
                "honeypot_events_24h": honeypot_24h,
                "pending_approvals": pending_approvals,
                "database": str(DB_PATH),
                "daemon_api": "http://localhost:8088",
            }

        elif name == "get_approvals":
            rows = db.execute(
                """SELECT a.*, p.ip, p.escalation_level
                   FROM approvals a JOIN attacker_profiles p ON a.profile_id = p.id
                   WHERE a.status = 'pending' ORDER BY a.created_at DESC"""
            ).fetchall()
            return [dict(r) for r in rows]

        elif name == "resolve_threat":
            threat_id = arguments["threat_id"]
            db.execute("UPDATE threats SET status = 'resolved' WHERE id = ?", (threat_id,))
            db.commit()
            return {"success": True, "threat_id": threat_id, "new_status": "resolved"}

        elif name == "get_threat_summary":
            rows = db.execute(
                """SELECT source_ip, threat_type, COUNT(*) as count,
                          MAX(severity) as severity, MAX(timestamp) as last_seen,
                          MIN(timestamp) as first_seen,
                          CASE WHEN SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) > 0 THEN 'open'
                               WHEN SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) > 0 THEN 'blocked'
                               ELSE 'resolved' END as status
                   FROM threats GROUP BY source_ip, threat_type
                   ORDER BY CASE WHEN SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) > 0 THEN 0 ELSE 1 END,
                            MAX(timestamp) DESC LIMIT 50"""
            ).fetchall()
            return [dict(r) for r in rows]

        elif name == "search_knowledge":
            # Simple file-based search in knowledge directory
            query = arguments.get("query", "")
            category = arguments.get("category")
            kb_path = Path(__file__).parent.parent / "knowledge"
            if not kb_path.exists():
                return {"error": "Knowledge base not found"}
            results = []
            pattern = f"{category}/**/*.md" if category else "**/*.md"
            for f in kb_path.glob(pattern):
                content = f.read_text(errors="replace")
                if query.lower() in content.lower():
                    # Extract surrounding context
                    idx = content.lower().index(query.lower())
                    start = max(0, idx - 200)
                    end = min(len(content), idx + 200)
                    results.append({
                        "file": str(f.relative_to(kb_path)),
                        "excerpt": content[start:end],
                    })
                    if len(results) >= 5:
                        break
            return results

        else:
            return {"error": f"Unknown tool: {name}"}
    finally:
        db.close()


# MCP stdio protocol handler
def main():
    """Simple MCP stdio server."""
    tools = [
        {"name": "get_threats", "description": "List threats from the AegisSIEM database",
         "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}, "status": {"type": "string", "enum": ["open", "blocked", "resolved"]}}}},
        {"name": "get_blocked_ips", "description": "List currently blocked IP addresses",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "get_profiles", "description": "List attacker profiles with recon data",
         "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}, "min_level": {"type": "integer", "default": 0}}}},
        {"name": "get_honeypot_events", "description": "List honeypot interaction events",
         "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}, "attacker_ip": {"type": "string"}}}},
        {"name": "get_status", "description": "Get overall AegisSIEM system status",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "get_approvals", "description": "List pending PROCEED/STOP approval checkpoints",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "resolve_threat", "description": "Mark a threat as resolved",
         "inputSchema": {"type": "object", "properties": {"threat_id": {"type": "integer"}}, "required": ["threat_id"]}},
        {"name": "get_threat_summary", "description": "Get aggregated threat summary grouped by IP and type",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "search_knowledge", "description": "Search the knowledge base for cybersecurity topics",
         "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "category": {"type": "string"}}, "required": ["query"]}},
    ]

    for line in sys.stdin:
        try:
            msg = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        if msg.get("method") == "tools/list":
            response = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": tools}}
        elif msg.get("method") == "tools/call":
            params = msg.get("params", {})
            result = handle_tool_call(params.get("name"), params.get("arguments", {}))
            response = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]}}
        elif msg.get("method") == "initialize":
            response = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "aegissiem", "version": "1.0.0"}}}
        else:
            response = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {}}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
