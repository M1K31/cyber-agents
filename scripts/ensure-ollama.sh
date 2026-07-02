#!/usr/bin/env bash
# ensure-ollama.sh — Ensure Ollama is running and qwen2.5-coder is available.
# Called by the AegisSIEM daemon at startup and can be run manually.

set -euo pipefail

OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
MODEL="${1:-qwen2.5-coder}"
MAX_WAIT=60

log() { printf '[ensure-ollama] %s\n' "$*"; }

# --- 1. Check if Ollama is running ---
check_ollama() {
    curl -sf "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1
}

if check_ollama; then
    log "Ollama is already running at ${OLLAMA_HOST}"
else
    log "Ollama not running. Starting ollama serve..."
    ollama serve &>/dev/null &
    OLLAMA_PID=$!
    log "Started ollama serve (PID ${OLLAMA_PID})"

    elapsed=0
    while ! check_ollama; do
        if [ $elapsed -ge $MAX_WAIT ]; then
            log "ERROR: Ollama did not start within ${MAX_WAIT}s"
            exit 1
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    log "Ollama is now running (took ${elapsed}s)"
fi

# --- 2. Ensure the model is pulled ---
if curl -sf "${OLLAMA_HOST}/api/tags" | grep -q "\"${MODEL}\""; then
    log "Model '${MODEL}' is already available"
else
    log "Pulling model '${MODEL}'... (this may take a while)"
    ollama pull "${MODEL}"
    log "Model '${MODEL}' pulled successfully"
fi

# --- 3. Verify OpenAI-compatible endpoint ---
if curl -sf "${OLLAMA_HOST}/v1/models" >/dev/null 2>&1; then
    log "OpenAI-compatible endpoint verified at ${OLLAMA_HOST}/v1/"
else
    log "WARNING: OpenAI-compatible endpoint not responding. Ollama may need updating."
fi

log "Ready. Model: ${MODEL} | Endpoint: ${OLLAMA_HOST}/v1/"
