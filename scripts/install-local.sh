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

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CYBER_HARNESS_PREFIX:-$HOME/.local/share/cyber-harness}"
VENV="$PREFIX/venv"
PY="${PYTHON_BIN:-python3.12}"
PORT="${CYBER_HARNESS_PORT:-8088}"
LABEL="com.smartindustries.cyber-harness"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
WRITE_PLIST=false
for a in "$@"; do case "$a" in --plist) WRITE_PLIST=true ;; esac; done

echo "==> Installing cyber-harness runtime to $PREFIX"
mkdir -p "$PREFIX" "$HOME/.cyber-harness"
[ -d "$VENV" ] || "$PY" -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel >/dev/null
[ -f "$REPO/daemon/requirements.txt" ] && "$VENV/bin/pip" install -r "$REPO/daemon/requirements.txt"
"$VENV/bin/pip" install "$REPO"

ECO_ROOT="${ECOSYSTEM_BASE_PATH:-$REPO/../..}/appEcosystem"
if [ -d "$ECO_ROOT" ]; then
    echo "==> Installing shared ecosystem packages from $ECO_ROOT"
    "$VENV/bin/pip" install "$ECO_ROOT/auth/python" "$ECO_ROOT/packages/ecosystem-client" \
                            "$ECO_ROOT/packages/ecosystem-ai"
else
    echo "!!  appEcosystem not found at $ECO_ROOT — provider routing unavailable" >&2
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
    <key>CYBER_HARNESS_PORT</key><string>$PORT</string>
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
