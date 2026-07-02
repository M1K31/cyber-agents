"""CLI installer for the Cyber Claude Harness.

Installs Claude Code agents, skills, commands, hooks, MCP servers,
and the AegisSIEM daemon into a target project directory.

Usage:
    cyber-harness install /path/to/AI-for-Survival --profile ai-survival
    cyber-harness install /path/to/LogAnalysis --profile loganalysis
    cyber-harness install /path/to/project --profile full
    cyber-harness status /path/to/project
    cyber-harness uninstall /path/to/project
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# Source directory: the cyber-claude-agents root.
# Works for both editable installs (pip install -e .) and direct execution.
HARNESS_ROOT = Path(__file__).parent.parent

def _find_harness_root() -> Path:
    """Locate the harness root directory containing agents/, skills/, etc."""
    # 1. Editable install or direct run: parent.parent has agents/
    candidate = Path(__file__).parent.parent
    if (candidate / "agents").is_dir():
        return candidate
    # 2. Installed via pip: check for a .harness-root marker
    marker = candidate / ".harness-root"
    if marker.exists():
        return Path(marker.read_text().strip())
    # 3. Environment variable override
    import os
    env_root = os.environ.get("CYBER_HARNESS_ROOT")
    if env_root:
        return Path(env_root)
    # 4. Fallback to the default
    return candidate

HARNESS_ROOT = _find_harness_root()

# Components available for installation
COMPONENTS = {
    "agents": {
        "source": "agents",
        "files": [
            "log-analyst.md",
            "network-guardian.md",
            "knowledge-agent.md",
            "threat-hunter.md",
            "incident-responder.md",
            "red-team-lead.md",
            "exploit-researcher.md",
        ],
    },
    "skills": {
        "source": "skills",
        "files": [
            "ollama-inference.md",
            "syslog-analysis.md",
            "router-management.md",
            "kali-linux-tooling.md",
            "macos-tooling.md",
            "defense-evasion.md",
            "yara-rule-creation.md",
        ],
    },
    "commands": {
        "source": "commands",
        "files": [
            "analyze.md",
            "block.md",
            "status.md",
            "triage.md",
            "scan.md",
            "hunt.md",
        ],
    },
    "rules": {
        "source": "rules",
        "files": [
            "opsec.md",
            "safe-harbor.md",
            "data-handling.md",
            "reporting-standards.md",
        ],
    },
    "contexts": {
        "source": "contexts",
        "files": ["research.md", "active-engagement.md"],
    },
    "hooks": {
        "source": "scripts/hooks",
        "files": [
            "pre-command-scope-check.js",
            "ioc-extractor.js",
            "post-session-sanitize.js",
            "threat-data-watcher.js",
            "ecosystem-event-publisher.js",
        ],
    },
    "mcp-configs": {
        "source": "mcp-configs",
        "files": [
            "aegissiem-mcp.json",
            "ecosystem-mcp.json",
            "shodan-mcp.json",
            "virustotal-mcp.json",
            "splunk-mcp.json",
        ],
    },
    "mcp-servers": {
        "source": "mcp-servers",
        "files": [
            "aegissiem-server.py",
            "ecosystem-server.py",
        ],
    },
    "dashboard": {
        "source": "dashboard",
        "files": ["index.html", "style.css", "app.js"],
    },
    "scripts": {
        "source": "scripts",
        "files": ["ensure-ollama.sh", "ollama-env.sh"],
    },
}

# Installation profiles — which components each project needs
PROFILES = {
    "ai-survival": {
        "description": "AI-for-Survival: Claude Code agents for LLM management + knowledge base",
        "components": [
            "agents", "skills", "commands", "rules", "contexts",
            "hooks", "mcp-configs", "mcp-servers", "scripts",
        ],
        "claude_md_template": "ai-survival",
    },
    "loganalysis": {
        "description": "LogAnalysis/AegisSIEM: Daemon + Claude Code agents for threat detection",
        "components": [
            "agents", "skills", "commands", "rules", "contexts",
            "hooks", "mcp-configs", "mcp-servers", "dashboard", "scripts",
        ],
        "claude_md_template": "loganalysis",
    },
    "full": {
        "description": "Full harness: all components for standalone deployment",
        "components": list(COMPONENTS.keys()),
        "claude_md_template": "full",
    },
}


def log(msg: str, level: str = "info"):
    prefix = {"info": "  ", "ok": "  [OK]", "skip": "  [--]", "err": "  [!!]"}
    print(f"{prefix.get(level, '  ')} {msg}")


def install_component(
    name: str, target_dir: Path, force: bool = False
) -> tuple[int, int]:
    """Install a component's files into the target directory.
    Returns (installed_count, skipped_count).
    """
    comp = COMPONENTS[name]
    source_dir = HARNESS_ROOT / comp["source"]
    target_sub = target_dir / comp["source"]
    target_sub.mkdir(parents=True, exist_ok=True)

    installed = 0
    skipped = 0

    for filename in comp["files"]:
        src = source_dir / filename
        dst = target_sub / filename

        if not src.exists():
            log(f"{name}/{filename}: source not found", "err")
            skipped += 1
            continue

        if dst.exists() and not force:
            log(f"{name}/{filename}: exists (use --force to overwrite)", "skip")
            skipped += 1
            continue

        shutil.copy2(src, dst)
        log(f"{name}/{filename}", "ok")
        installed += 1

    return installed, skipped


def install_hooks_json(target_dir: Path, force: bool = False):
    """Install or merge hooks.json into the target project."""
    src = HARNESS_ROOT / "hooks" / "hooks.json"
    target_hooks_dir = target_dir / "hooks"
    target_hooks_dir.mkdir(parents=True, exist_ok=True)
    dst = target_hooks_dir / "hooks.json"

    if not src.exists():
        log("hooks.json: source not found", "err")
        return

    if dst.exists() and not force:
        # Merge: add our hooks to existing
        try:
            existing = json.loads(dst.read_text())
            new_hooks = json.loads(src.read_text())

            for event_type, hook_list in new_hooks.get("hooks", {}).items():
                if event_type not in existing.get("hooks", {}):
                    existing.setdefault("hooks", {})[event_type] = hook_list
                else:
                    # Add hooks that don't already exist (by command)
                    existing_cmds = set()
                    for entry in existing["hooks"][event_type]:
                        for h in entry.get("hooks", []):
                            existing_cmds.add(h.get("command", ""))

                    for entry in hook_list:
                        new_entry_hooks = []
                        for h in entry.get("hooks", []):
                            if h.get("command", "") not in existing_cmds:
                                new_entry_hooks.append(h)
                        if new_entry_hooks:
                            existing["hooks"][event_type].append(
                                {**entry, "hooks": new_entry_hooks}
                            )

            dst.write_text(json.dumps(existing, indent=2) + "\n")
            log("hooks.json: merged with existing", "ok")
        except (json.JSONDecodeError, KeyError) as e:
            log(f"hooks.json: merge failed ({e}), skipping", "err")
    else:
        shutil.copy2(src, dst)
        log("hooks.json: installed", "ok")


def install_claude_md(target_dir: Path, profile: str, force: bool = False):
    """Install or update CLAUDE.md in the target project."""
    src = HARNESS_ROOT / "CLAUDE.md"
    dst = target_dir / "CLAUDE.md"

    if dst.exists() and not force:
        # Append a section pointing to the harness
        content = dst.read_text()
        marker = "## Cyber Claude Harness"
        if marker in content:
            log("CLAUDE.md: harness section already present", "skip")
            return

        harness_section = f"""
{marker}

This project includes the Cyber Claude Harness for cybersecurity operations.
See the full harness documentation in the installed components.

### Installed Components
- Agents: `agents/` (log-analyst, network-guardian, knowledge-agent, etc.)
- Skills: `skills/` (ollama-inference, syslog-analysis, router-management, etc.)
- Commands: `/analyze`, `/block`, `/status`, `/triage`, `/scan`, `/hunt`
- Hooks: `scripts/hooks/` (scope check, IOC extractor, threat watcher, etc.)
- MCP Servers: `mcp-servers/` (aegissiem, ecosystem)

### Ollama Integration
1. Ensure Ollama is running: `scripts/ensure-ollama.sh`
2. Source environment: `source scripts/ollama-env.sh`
3. Start Claude Code: `claude`

### AegisSIEM Daemon
Start: `aegissiem-daemon` (or `python -m daemon.aegissiem_daemon`)
Config: `~/.aegissiem-daemon/config.yml`
Dashboard: `http://localhost:8088`
"""
        dst.write_text(content + harness_section)
        log("CLAUDE.md: appended harness section", "ok")
    else:
        shutil.copy2(src, dst)
        log("CLAUDE.md: installed", "ok")


def install_vault(target_dir: Path):
    """Create vault directories for data storage."""
    vault = target_dir / "vault"
    (vault / "threat-data").mkdir(parents=True, exist_ok=True)
    log("vault/threat-data/: created", "ok")


def install_authorized_scope(target_dir: Path):
    """Install authorized_scope.json if not present."""
    src = HARNESS_ROOT / "scripts" / "authorized_scope.json"
    dst = target_dir / "scripts" / "authorized_scope.json"
    if src.exists() and not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        log("scripts/authorized_scope.json: installed", "ok")


def cmd_install(args):
    """Install harness components into a target project."""
    target = Path(args.target).resolve()
    profile_name = args.profile
    force = args.force

    if not target.exists():
        print(f"Error: target directory does not exist: {target}")
        sys.exit(1)

    if profile_name not in PROFILES:
        print(f"Error: unknown profile '{profile_name}'. Available: {', '.join(PROFILES.keys())}")
        sys.exit(1)

    profile = PROFILES[profile_name]
    print(f"\nInstalling Cyber Claude Harness ({profile_name})")
    print(f"  Profile: {profile['description']}")
    print(f"  Target:  {target}")
    print(f"  Force:   {force}")
    print()

    total_installed = 0
    total_skipped = 0

    for comp_name in profile["components"]:
        print(f"[{comp_name}]")
        installed, skipped = install_component(comp_name, target, force)
        total_installed += installed
        total_skipped += skipped

    print("\n[hooks.json]")
    install_hooks_json(target, force)

    print("\n[CLAUDE.md]")
    install_claude_md(target, profile_name, force)

    print("\n[vault]")
    install_vault(target)

    print("\n[authorized_scope]")
    install_authorized_scope(target)

    print(f"\nDone. Installed {total_installed} files, skipped {total_skipped}.")
    print(f"\nNext steps:")
    print(f"  1. cd {target}")
    print(f"  2. ./scripts/ensure-ollama.sh        # Ensure Ollama + qwen2.5-coder")
    print(f"  3. source scripts/ollama-env.sh       # Configure Claude Code env")
    print(f"  4. aegissiem-daemon &                 # Start daemon (optional)")
    print(f"  5. claude                             # Launch Claude Code")


def cmd_status(args):
    """Show installation status for a target project."""
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"Error: directory does not exist: {target}")
        sys.exit(1)

    print(f"\nCyber Claude Harness — Installation Status")
    print(f"Target: {target}\n")

    for comp_name, comp in COMPONENTS.items():
        source_dir = comp["source"]
        present = 0
        total = len(comp["files"])
        for filename in comp["files"]:
            if (target / source_dir / filename).exists():
                present += 1
        status = "complete" if present == total else f"{present}/{total}"
        icon = "+" if present == total else ("~" if present > 0 else "-")
        print(f"  [{icon}] {comp_name:15s} {status}")

    # Check hooks.json
    hooks_path = target / "hooks" / "hooks.json"
    print(f"  [{'+'if hooks_path.exists() else '-'}] {'hooks.json':15s}")

    # Check CLAUDE.md
    claude_md = target / "CLAUDE.md"
    has_harness = False
    if claude_md.exists():
        has_harness = "Cyber Claude Harness" in claude_md.read_text()
    print(f"  [{'+'if has_harness else ('~' if claude_md.exists() else '-')}] {'CLAUDE.md':15s} {'(harness section present)' if has_harness else ''}")

    # Check vault
    vault = target / "vault" / "threat-data"
    print(f"  [{'+'if vault.exists() else '-'}] {'vault/threat-data':15s}")


def cmd_uninstall(args):
    """Remove harness components from a target project."""
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"Error: directory does not exist: {target}")
        sys.exit(1)

    print(f"\nUninstalling Cyber Claude Harness from {target}\n")

    removed = 0
    for comp_name, comp in COMPONENTS.items():
        for filename in comp["files"]:
            filepath = target / comp["source"] / filename
            if filepath.exists():
                filepath.unlink()
                log(f"Removed {comp['source']}/{filename}", "ok")
                removed += 1

    # Remove empty component directories (but not if they have other files)
    for comp_name, comp in COMPONENTS.items():
        comp_dir = target / comp["source"]
        if comp_dir.exists() and not any(comp_dir.iterdir()):
            comp_dir.rmdir()
            log(f"Removed empty directory {comp['source']}/", "ok")

    print(f"\nRemoved {removed} files.")
    print("Note: CLAUDE.md and hooks.json were not modified. Edit manually if needed.")


def main():
    parser = argparse.ArgumentParser(
        prog="cyber-harness",
        description="Cyber Claude Harness — Install cybersecurity Claude Code agents into projects",
    )
    sub = parser.add_subparsers(dest="command")

    p_install = sub.add_parser("install", help="Install harness into a project")
    p_install.add_argument("target", help="Target project directory")
    p_install.add_argument(
        "--profile", "-p",
        choices=list(PROFILES.keys()),
        default="full",
        help="Installation profile (default: full)",
    )
    p_install.add_argument(
        "--force", "-f",
        action="store_true",
        help="Overwrite existing files",
    )

    p_status = sub.add_parser("status", help="Show installation status")
    p_status.add_argument("target", help="Target project directory")

    p_uninstall = sub.add_parser("uninstall", help="Remove harness from a project")
    p_uninstall.add_argument("target", help="Target project directory")

    args = parser.parse_args()

    commands = {
        "install": cmd_install,
        "status": cmd_status,
        "uninstall": cmd_uninstall,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
