# 🔐 Zero-Trust AI Access Layer

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](https://github.com/yksanjo/zero-trust-ai-access/pulls)

**Context-aware authentication for AI agents** — a zero-trust access layer that verifies every request to LLM APIs, tool calls, and data sources.

> Never trust, always verify — even for AI agents.

---

## 🚨 The Problem

AI agents today operate with **implicit trust**:
- Once authenticated, they can call any tool or API
- No per-request authorization checks
- No context-aware access control
- Prompt injection can bypass existing guards

## ✅ The Solution

Zero-Trust AI Access Layer applies **continuous verification** to every agent action:

```
Agent Request → Identity Check → Context Evaluation → Policy Decision → Allow/Deny
```

---

## ✨ Features

- **🔑 Per-Request Authentication** — Every tool call and API request is independently verified
- **🧠 Context-Aware Policies** — Access decisions based on conversation context, intent, and risk score
- **🛡️ Prompt Injection Detection** — Identifies and blocks injection attempts before they reach the LLM
- **📝 Audit Trail** — Complete log of every access decision for compliance and debugging
- **⚡ Minimal Latency** — Sub-100ms decision time for most requests
- **🔌 Framework Agnostic** — Works with any LLM, agent framework, or tool chain

---

## 🚀 Quick Start

```bash
# Install
pip install zero-trust-ai-access

# Basic usage
from zero_trust import AccessGate

gate = AccessGate()
result = gate.evaluate(
    agent_id="my-agent",
    action="read_file",
    context={"path": "/etc/passwd", "intent": "system_config"}
)
# result.allowed → False
```

---

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  AI Agent   │────▶│  Access Gate     │────▶│  LLM / Tool  │
└─────────────┘     └──────────────────┘     └──────────────┘
                           │
                    ┌──────┴──────┐
                    │  Policy     │
                    │  Engine     │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │  Audit Log  │
                    └─────────────┘
```

---

## 📋 Policy Examples

```yaml
# policies.yaml
policies:
  - name: "restrict-file-access"
    action: "read_file"
    conditions:
      path: "/app/data/*"  # Only allow app data directory
    deny_paths:
      - "/etc/*"
      - "/.env*"
    risk_threshold: 0.7

  - name: "api-rate-limit"
    action: "call_api"
    max_per_minute: 60
    sensitive_endpoints:
      - "/api/admin/*"
      - "/api/billing/*"
```

---

## 🔧 Configuration

```bash
# Environment variables
export ZTAI_POLICY_FILE="./policies.yaml"
export ZTAI_AUDIT_LOG="./audit.log"
export ZTAI_RISK_THRESHOLD="0.7"
```

---

## 📊 Use Cases

| Use Case | Description |
|----------|-------------|
| **Agent Sandboxing** | Restrict what tools/APIs an agent can access per-session |
| **Multi-Tenant AI** | Isolate agent access between different users/organizations |
| **CI/CD Agents** | Prevent automated agents from accessing production resources |
| **Research Agents** | Allow web access but block internal tools |

---

## 🤝 Contributing

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT

---

<div align="center">
  <strong>⭐ Star if you use it — it helps others find this project!</strong>
</div>
