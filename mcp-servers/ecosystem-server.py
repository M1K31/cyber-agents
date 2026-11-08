#!/usr/bin/env python3
"""Ecosystem MCP Server — Bridges Claude Code with appEcosystem service registry, events, and policy engine."""

import json
import os
import sys
from pathlib import Path
import httpx

REGISTRY_URL = os.environ.get("ECOSYSTEM_REGISTRY_URL", "http://localhost:8500").rstrip("/")


def _ensure_ecosystem_auth() -> None:
    env = os.environ.get("APP_ECOSYSTEM_PATH")
    candidates = [Path(env).expanduser()] if env else []
    for parent in Path(__file__).resolve().parents:
        candidates.append(parent / "appEcosystem")
    for root in candidates:
        if root.is_dir():
            for rel in ("auth/python", "packages/ecosystem-client", "packages/ecosystem-policy"):
                p = (root / rel).resolve()
                if p.is_dir() and str(p) not in sys.path:
                    sys.path.insert(0, str(p))
            break


def _signed_headers(method: str, url: str, body: dict | None = None) -> dict:
    _ensure_ecosystem_auth()
    try:
        from ecosystem_auth.tokens import get_ecosystem_secret, sign_request

        secret = get_ecosystem_secret()
        return sign_request(method, url, secret, body=body)
    except Exception:
        return {}


def handle_tool_call(name, arguments):
    try:
        if name == "publish_event":
            event_type = arguments["event_type"]
            data = arguments.get("data", {})
            url = f"{REGISTRY_URL}/events/publish"
            payload = {
                "event_type": event_type,
                "source": "aegissiem_daemon",
                "data": data,
            }
            headers = _signed_headers("POST", url, payload)
            if not headers:
                # Signing failed (e.g. ECOSYSTEM_SECRET missing). Surface the local
                # configuration error instead of silently sending an unsigned request
                # the registry would reject anyway.
                return {"success": False, "error": "Request signing failed (missing ecosystem secret?); not sending unsigned"}
            with httpx.Client(timeout=10) as client:
                resp = client.post(url, json=payload, headers=headers)
                return {"success": resp.status_code == 200, "status_code": resp.status_code}

        elif name == "get_policy_state":
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{REGISTRY_URL}/policy/state")
                if resp.status_code == 200:
                    return resp.json()
                return {"error": f"Registry returned {resp.status_code}"}

        elif name == "check_policy":
            url = f"{REGISTRY_URL}/policy/decide"
            payload = {
                "actor": arguments.get("actor", "cyber_agents/mcp"),
                "action": arguments["action"],
                "action_class": arguments["action_class"],
                "target": arguments.get("target", {}),
                "rationale": arguments.get("rationale", ""),
            }
            headers = _signed_headers("POST", url, payload)
            with httpx.Client(timeout=5) as client:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    return resp.json()
                return {"error": f"Policy decide returned {resp.status_code}: {resp.text}"}

        elif name == "discover_service":
            service_name = arguments["service_name"]
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{REGISTRY_URL}/services")
                if resp.status_code == 200:
                    services = resp.json()
                    for svc in services:
                        if svc.get("name") == service_name:
                            return svc
                    return {"error": f"Service '{service_name}' not found"}
                return {"error": f"Registry returned {resp.status_code}"}

        elif name == "get_registry_status":
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{REGISTRY_URL}/services")
                if resp.status_code == 200:
                    services = resp.json()
                    return {
                        "registry_url": REGISTRY_URL,
                        "services": services,
                        "service_count": len(services),
                    }
                return {"error": f"Registry returned {resp.status_code}"}

        else:
            return {"error": f"Unknown tool: {name}"}

    except httpx.ConnectError:
        return {"error": f"Cannot connect to ecosystem registry at {REGISTRY_URL}. Is it running?"}
    except Exception as e:
        return {"error": str(e)}


def main():
    tools = [
        {"name": "publish_event", "description": "Publish a signed event to the ecosystem event bus",
         "inputSchema": {"type": "object", "properties": {
             "event_type": {"type": "string", "description": "Event type (e.g., security.alert, security.threat_blocked)"},
             "data": {"type": "object", "description": "Event payload data"}
         }, "required": ["event_type"]}},
        {"name": "get_policy_state", "description": "Inspect active ecosystem blue-team policy state, Freeze status, and Restrictions: Off grants",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "check_policy", "description": "Evaluate an ActionRequest against the authoritative PolicyEngine before executing mutating or investigative actions",
         "inputSchema": {"type": "object", "properties": {
             "actor": {"type": "string", "description": "Actor identifier (default: cyber_agents/mcp)"},
             "action": {"type": "string", "description": "Action name (e.g., block_ip, zbt_scan, triage)"},
             "action_class": {"type": "string", "enum": ["observe", "investigate", "contain", "remediate", "data_release", "system_change"]},
             "target": {"type": "object", "description": "Target metadata (device_id, router, external_ip, etc.)"},
             "rationale": {"type": "string", "description": "Reason for the action"}
         }, "required": ["action", "action_class"]}},
        {"name": "discover_service", "description": "Discover a peer service in the ecosystem",
         "inputSchema": {"type": "object", "properties": {
             "service_name": {"type": "string", "description": "Service name (e.g., openeye, ai_for_survival, magicmirror)"}
         }, "required": ["service_name"]}},
        {"name": "get_registry_status", "description": "Get ecosystem registry status and list all registered services",
         "inputSchema": {"type": "object", "properties": {}}},
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
            response = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "ecosystem", "version": "1.0.0"}}}
        else:
            response = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {}}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
