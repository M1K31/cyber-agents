#!/usr/bin/env bash
# Install the Cyber Claude harness daemon (aegissiem_daemon, port 8088).
#
# Bundled but OPT-IN: this sets the runtime up; the daemon only runs when you
# install the LaunchAgent with --plist. Runtime lives on the INTERNAL disk (the
# repo may sit on an external volume, where a force-unmount SIGBUSes mmap'd
# C-extensions).
#
#   ./scripts/install-local.sh            # venv + deps only (no service)
#   ./scripts/install-local.sh --plist    # also install + load the LaunchAgent
set -euo pipefail

# Distros disagree on which Python minor they ship, so honour the project
# minimum (3.10) instead of one exact version: pinning python3.12 fails on
# Debian bookworm (3.11), Ubuntu 22.04 (3.10), and anything newer.
_resolve_python() {
    local c
    for c in python3.13 python3.12 python3.11 python3.10 python3; do
        command -v "$c" >/dev/null 2>&1 || continue
        "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null \
            && { echo "$c"; return 0; }
    done
    return 1
}

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CYBER_HARNESS_PREFIX:-$HOME/.local/share/cyber-harness}"
VENV="$PREFIX/venv"
PY="${PYTHON_BIN:-$(_resolve_python || true)}"
if [ -z "$PY" ] || ! command -v "$PY" >/dev/null 2>&1; then
    echo "ERROR: no Python >= 3.10 found (set PYTHON_BIN to override)"; exit 1
fi
PORT="${CYBER_HARNESS_PORT:-8088}"
LABEL="com.smartindustries.cyber-harness"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
WRITE_PLIST=false
for a in "$@"; do case "$a" in --plist) WRITE_PLIST=true ;; esac; done

# The daemon's real state dir (db, config.yml, vault/threat-data) is
# ~/.aegissiem-daemon — see daemon/db.py:DEFAULT_DB_PATH and
# daemon/aegissiem_daemon.py:CONFIG_PATH/VAULT_THREAT_DIR. It is NOT
# ~/.cyber-harness (an older, unused path) and it is NOT ~/.aegissiem
# (AegisSIEM's own state dir, a different project). Keep this literal —
# do not derive it from PREFIX or any other path.
STATE_DIR="${CYBER_HARNESS_STATE_DIR:-$HOME/.aegissiem-daemon}"

echo "==> Installing cyber-harness runtime to $PREFIX"
mkdir -p "$PREFIX" "$STATE_DIR"

# One-time migration cleanup: an earlier version of this installer created
# ~/.cyber-harness, which the daemon never reads. Only remove it here if it
# is empty (rmdir, not rm -rf) so we never touch real data by accident.
LEGACY_STATE_DIR="$HOME/.cyber-harness"
if [ -d "$LEGACY_STATE_DIR" ]; then
    rmdir "$LEGACY_STATE_DIR" 2>/dev/null \
        && echo "==> Removed unused legacy dir $LEGACY_STATE_DIR" \
        || echo "!!  $LEGACY_STATE_DIR exists and is non-empty — leaving it in place" >&2
fi

[ -d "$VENV" ] || "$PY" -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel >/dev/null
[ -f "$REPO/daemon/requirements.txt" ] && "$VENV/bin/pip" install -r "$REPO/daemon/requirements.txt"
"$VENV/bin/pip" install "$REPO"

# The shared ecosystem packages are ordinary dependencies in pyproject.toml, so
# the `pip install "$REPO"` above already pulled them from PyPI. The harness is
# an ecosystem component — it is registered in ecosystem.yaml as the preferred
# security-analysis backend — so they are not optional. The previous block
# printed a warning and continued when the sibling checkout was missing, which
# left provider routing quietly unavailable.
#
# ECOSYSTEM_FROM_SOURCE=1 replaces them with EDITABLE installs from a local
# checkout, for developing the packages themselves, and fails loudly when the
# checkout is absent rather than leaving the PyPI copies silently in place.
if [ -n "${ECOSYSTEM_FROM_SOURCE:-}" ]; then
    ECO_ROOT="${ECOSYSTEM_BASE_PATH:-$REPO/../..}/appEcosystem"
    if [ ! -d "$ECO_ROOT/auth/python" ]; then
        echo "ERROR: ECOSYSTEM_FROM_SOURCE=1 but no appEcosystem checkout at $ECO_ROOT" >&2
        exit 1
    fi
    echo "==> Overriding ecosystem packages with EDITABLE source installs from $ECO_ROOT"
    "$VENV/bin/pip" install -e "$ECO_ROOT/auth/python" \
                            -e "$ECO_ROOT/packages/ecosystem-client" \
                            -e "$ECO_ROOT/packages/ecosystem-ai" \
        || { echo "ERROR: editable ecosystem install failed" >&2; exit 1; }
fi

if $WRITE_PLIST; then
    LOGDIR="$HOME/Library/Logs/CyberHarness"
    mkdir -p "$LOGDIR" "$HOME/Library/LaunchAgents"
    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$VENV/bin/python</string>
    <string>-m</string><string>daemon.aegissiem_daemon</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>HOME</key><string>$HOME</string>
    <key>AEGISSIEM_PORT</key><string>$PORT</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOGDIR/stdout.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/stderr.log</string>
</dict></plist>
PLIST_EOF
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST"
    echo "==> LaunchAgent loaded ($LABEL, port $PORT)"
else
    echo "==> Runtime ready (opt-in). Enable the service with: $0 --plist"
fi
