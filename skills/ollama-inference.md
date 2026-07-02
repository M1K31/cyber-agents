---
name: Ollama Inference
description: Patterns for calling Ollama's qwen2.5-coder model for LLM-powered analysis
---

# Ollama Inference Skill

Use these patterns to call the local Ollama qwen2.5-coder model for analysis tasks.

## Chat Completion
```bash
curl -s http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5-coder",
    "messages": [
      {"role": "system", "content": "SYSTEM_PROMPT"},
      {"role": "user", "content": "USER_MESSAGE"}
    ],
    "temperature": 0.7,
    "max_tokens": 2048
  }' | jq -r '.choices[0].message.content'
```

## Streaming (for long analysis)
```bash
curl -N http://localhost:11434/api/chat \
  -d '{
    "model": "qwen2.5-coder",
    "messages": [{"role": "user", "content": "MESSAGE"}],
    "stream": true
  }'
```

## Model Management
```bash
# List available models
curl -s http://localhost:11434/api/tags | jq '.models[].name'

# Check model is loaded
curl -s http://localhost:11434/api/tags | jq '.models[] | select(.name | contains("qwen2.5-coder"))'

# Pull model if missing
ollama pull qwen2.5-coder
```

## Health Check
```bash
curl -sf http://localhost:11434/api/tags >/dev/null && echo "Ollama OK" || echo "Ollama DOWN"
```

## Security Analysis Prompts

### Threat Analysis
System: "You are a cybersecurity threat analyst specializing in network intrusion detection. Analyze attacker profiles and provide threat assessments with MITRE ATT&CK technique mappings."

### Log Analysis
System: "You are a security log analyst. Parse and analyze router syslog data. Identify patterns, anomalies, and potential security incidents. Map findings to common attack techniques."

### Incident Triage
System: "You are an incident responder performing initial triage. Assess the severity, determine scope, identify affected systems, and recommend immediate actions."
