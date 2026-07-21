#!/usr/bin/env bash
#
# uninstall.sh — Remove the cyber-harness daemon completely (FULL removal by default).
#
# Removes: the running process, the LaunchAgent (com.smartindustries.cyber-harness),
# the internal-disk runtime (~/.local/share/cyber-harness), logs in
# ~/Library/Logs/CyberHarness, and local state in ~/.aegissiem-daemon (detection
# history, honeypot events, SQLite DBs — see daemon/db.py and
# daemon/aegissiem_daemon.py for the source-of-truth paths).
#
# This deletes stored threats, approvals, and honeypot events. To keep them for a
# later reinstall, use the sibling script that preserves user data.
#
# Only paths owned by this project are touched.
#
# SAFETY: the state dir this script deletes is ~/.aegissiem-daemon, spelled
# out literally below. That is a DIFFERENT directory from AegisSIEM's own
# state dir (a different project, one directory name that is one suffix
# shorter). This script must never touch that other directory. Do not
# "simplify" STATE_DIR by trimming the "-daemon" suffix or building it from
# a shared prefix/glob — that exact class of cross-project deletion bug has
# already been found and fixed once in this ecosystem.
#
# Usage:
#   ./scripts/uninstall.sh              # FULL removal (asks to confirm)
#   ./scripts/uninstall.sh --yes        # FULL removal, no prompt (CI/automation)
#   ./scripts/uninstall.sh --dry-run    # print what would happen
#   ./scripts/uninstall-keep-data.sh    # remove service+runtime, KEEP state dir
#
set -euo pipefail

LABEL="com.smartindustries.cyber-harness"
PREFIX="${CYBER_HARNESS_PREFIX:-$HOME/.local/share/cyber-harness}"
STATE_DIR="${CYBER_HARNESS_STATE_DIR:-$HOME/.aegissiem-daemon}"
# One-time-migration leftover from an earlier installer version; the daemon
# never reads this path. Removed unconditionally below via bare rmdir (only
# succeeds if empty), never rm -rf, so it is safe even if something unexpected
# is in there.
LEGACY_STATE_DIR="$HOME/.cyber-harness"
LOG_DIR="$HOME/Library/Logs/CyberHarness"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

KEEP_DATA=false; DRY=false
NONINTERACTIVE="${CYBER_HARNESS_NONINTERACTIVE:-${CI:-}}"
for a in "$@"; do
    case "$a" in
        --keep-data)                KEEP_DATA=true ;;
        -y|--yes|--non-interactive) NONINTERACTIVE=1 ;;
        --dry-run)                  DRY=true ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "Unknown option: $a"; exit 1 ;;
    esac
done
run() { if $DRY; then echo "[dry-run] $*"; else eval "$*"; fi; }

if $KEEP_DATA; then
    echo "==> Uninstalling cyber-harness — keeping user data ($STATE_DIR)."
else
    echo "==> Uninstalling cyber-harness — FULL removal (deletes threats/approvals/state)."
    if [ -z "$NONINTERACTIVE" ] && ! $DRY; then
        read -rp "Type 'yes' to permanently delete all cyber-harness data: " confirm
        [ "$confirm" = "yes" ] || { echo "Aborted."; exit 1; }
    fi
fi

# Stray process (manual runs, not managed by launchd)
echo "==> Stopping any stray daemon.aegissiem_daemon process..."
run "pkill -f 'daemon\.aegissiem_daemon' 2>/dev/null || true"

# macOS LaunchAgent
if [[ -f "$PLIST" ]]; then
    echo "==> Removing LaunchAgent..."
    run "launchctl bootout gui/\$(id -u)/$LABEL 2>/dev/null || launchctl unload -w \"$PLIST\" 2>/dev/null || true"
    run "rm -f \"$PLIST\""
fi

# Internal-disk runtime
if [[ -d "$PREFIX" ]]; then
    echo "==> Removing internal runtime at $PREFIX..."
    run "rm -rf \"$PREFIX\""
fi

# Logs
if [[ -d "$LOG_DIR" ]]; then
    echo "==> Removing logs at $LOG_DIR..."
    run "rm -rf \"$LOG_DIR\""
fi

if $KEEP_DATA; then
    echo "==> Kept user data in $STATE_DIR."
else
    echo "==> Deleting user state $STATE_DIR..."
    run "rm -rf \"$STATE_DIR\""
fi

# Legacy unused dir cleanup — safe in both modes: bare rmdir only removes it
# if it's empty, and it never held real data (the daemon never wrote there).
if [[ -d "$LEGACY_STATE_DIR" ]]; then
    echo "==> Removing unused legacy dir $LEGACY_STATE_DIR (if empty)..."
    run "rmdir \"$LEGACY_STATE_DIR\" 2>/dev/null || true"
fi

echo "==> cyber-harness uninstalled. Reinstall with: ./scripts/install-local.sh"
