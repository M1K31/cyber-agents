#!/usr/bin/env bash
# Uninstall the cyber-harness daemon but KEEP local state (~/.cyber-harness:
# detection history, honeypot events, SQLite DBs).
#
# For a complete wipe use ./scripts/uninstall.sh
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/uninstall.sh" --keep-data "$@"
