#!/usr/bin/env python3
"""Ecosystem MCP Server — Bridges Claude Code with appEcosystem service registry and events."""

import json
import sys
import httpx

REGISTRY_URL = "http://localhost:8500"


def handle_tool_call(name, arguments):
    try:
        if name == "publish_event":
            event_type = arguments["event_type"]
            data = arguments.get("data", {})
            with httpx.Client(timeout=10) as client:
                resp = client.post(f"{REGISTRY_URL}/events/publish", json={
                    "event_type": event_type,
                    "source": "aegissiem_daemon",
                    "data": data,
                })
                return {"success": resp.status_code == 200, "status_code": resp.status_code}

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
        {"name": "publish_event", "description": "Publish an event to the ecosystem event bus",
         "inputSchema": {"type": "object", "properties": {
             "event_type": {"type": "string", "description": "Event type (e.g., security.alert, security.threat_blocked)"},
             "data": {"type": "object", "description": "Event payload data"}
         }, "required": ["event_type"]}},
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
