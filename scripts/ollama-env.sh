#!/usr/bin/env bash
# ollama-env.sh — Source this file to configure Claude Code to use Ollama.
#
# Usage:
#   source scripts/ollama-env.sh
#   claude                           # starts Claude Code with qwen2.5-coder
#   claude --model mistral           # override model per-session
#
# The OPENAI_API_KEY is set to "ollama" because Ollama accepts any value
# but Claude Code requires a non-empty key for third-party providers.

export CLAUDE_CODE_USE_BEDROCK=0
export CLAUDE_MODEL="${CLAUDE_MODEL:-qwen2.5-coder}"
export OPENAI_BASE_URL="${OLLAMA_HOST:-http://localhost:11434}/v1"
export OPENAI_API_KEY="ollama"

echo "[ollama-env] Configured Claude Code → Ollama"
echo "  Model:    ${CLAUDE_MODEL}"
echo "  Endpoint: ${OPENAI_BASE_URL}"
