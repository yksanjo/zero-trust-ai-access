# Zero-Trust AI Access Gateway

> **Okta for AI APIs** - Enterprise-grade Zero-Trust access layer for AI models

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

The **Zero-Trust AI Access Gateway** is a security-focused API gateway that sits between your applications and AI model providers (OpenAI, Anthropic, local LLMs). It provides enterprise-grade access control, security scanning, and audit logging for AI API usage.

### Key Features

- 🔐 **Zero-Trust Authentication** - OAuth2/OIDC integration with JWT validation
- 🛡️ **Security Scanning** - PII detection (Microsoft Presidio) & prompt injection detection
- 📊 **Rate Limiting** - Per-user and per-organization rate limits with Redis
- 💰 **Token Budgeting** - Track and limit token usage per user/organization
- 📜 **Policy Engine** - Dynamic policy enforcement for access control
- 📝 **Audit Logging** - Comprehensive request/response logging to PostgreSQL
- ☸️ **Kubernetes Ready** - Helm charts for production deployment
- 📈 **Observability** - Prometheus metrics and structured logging

## Architecture

```
┌─────────────┐     ┌─────────────────────────┐     ┌─────────────────┐
│  Client App │────▶│  Zero-Trust AI Gateway  │────▶│  OpenAI/Claude  │
│             │     │                         │     │  /Local LLM     │
└─────────────┘     │  • OAuth2/JWT Auth      │     └─────────────────┘
                    │  • Rate Limiting        │
                    │  • PII Detection        │
                    │  • Prompt Injection     │
                    │    Detection            │
                    │  • Policy Enforcement   │
                    │  • Audit Logging        │
                    │  • Token Budgeting      │
                    └─────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
            ┌──────────┐         ┌──────────┐
            │ PostgreSQL│         │  Redis   │
            │ (Audit)  │         │ (Cache)  │
            └──────────┘         └──────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for local development)
- Kubernetes cluster (for production)
- PostgreSQL 14+
- Redis 7+

### Local Development

1. **Clone and setup:**
```bash
git clone <repository-url>
cd zero-trust-ai-access
cp .env.example .env
# Edit .env with your configuration
```

2. **Start with Docker Compose:**
```bash
# Start core services (gateway, postgres, redis)
docker-compose up -d

# Or with monitoring (prometheus, grafana)
docker-compose --profile monitoring up -d
```

3. **Access the services:**
- Gateway: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Redis Commander: http://localhost:8081
- pgAdmin: http://localhost:8082 (admin/admin)
- Grafana: http://localhost:3000 (admin/admin) - with monitoring profile

### Manual Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Download Presidio models
python -m spacy download en_core_web_lg

# Run the gateway
python -m app.main
```

## API Usage

### Authentication

The gateway supports two authentication methods:

#### 1. JWT Tokens (OAuth2/OIDC)
```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

#### 2. API Keys
```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer ztai_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### OpenAI-Compatible Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/chat/completions` | Chat completions with full security pipeline |
| `POST /v1/completions` | Text completions (legacy) |
| `POST /v1/embeddings` | Text embeddings |
| `GET /v1/models` | List available models |

### Admin Endpoints

| Endpoint | Description | Auth Required |
|----------|-------------|---------------|
| `GET /health` | Health check | None |
| `GET /metrics` | Prometheus metrics | None |
| `GET /admin/stats` | Gateway statistics | Admin, Analyst |
| `GET /admin/users/{id}/usage` | User token usage | Admin, Owner |
| `GET /audit/logs` | Query audit logs | Admin, Analyst |
| `GET /policies/` | List policies | Any |
| `POST /policies/validate` | Validate request | Any |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://...` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `SECRET_KEY` | Application secret key | Required |
| `JWT_PUBLIC_KEY` | RSA public key for JWT validation | Optional |
| `OAUTH2_PROVIDER_URL` | OAuth2/OIDC provider URL | Required |
| `OPENAI_API_KEY` | OpenAI API key | Optional |
| `ANTHROPIC_API_KEY` | Anthropic API key | Optional |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | Per-user rate limit | 60 |
| `DEFAULT_USER_DAILY_TOKEN_LIMIT` | Daily token budget | 100000 |
| `PII_DETECTION_ENABLED` | Enable PII scanning | true |
| `PROMPT_INJECTION_DETECTION_ENABLED` | Enable injection detection | true |

See `.env.example` for complete configuration options.

## Security Features

### PII Detection (Microsoft Presidio)

Automatically detects and optionally anonymizes:
- Email addresses
- Phone numbers
- Credit card numbers
- Social Security Numbers
- IP addresses
- Names and locations
- And more...

### Prompt Injection Detection

Detects common attack patterns:
- "Ignore previous instructions"
- System prompt extraction attempts
- Role switching attacks
- Delimiter manipulation
- Jailbreak attempts

### Policy Engine

Dynamic policies for:
- Role-based access control
- Model restrictions per user/role
- Content filtering
- Time-based access
- IP allowlisting

## Deployment

### Kubernetes with Helm

```bash
# Add required Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install with default values
helm install zero-trust-ai ./helm \
  --namespace zero-trust-ai \
  --create-namespace

# Or with custom values
helm install zero-trust-ai ./helm \
  --namespace zero-trust-ai \
  --create-namespace \
  -f values-production.yaml \
  --set secrets.openai_api_key="sk-..." \
  --set secrets.anthropic_api_key="sk-ant-..."
```

### Production Considerations

1. **Secrets Management**: Use external secret stores (Vault, AWS Secrets Manager)
2. **TLS**: Configure certificates via cert-manager
3. **Network Policies**: Restrict pod-to-pod communication
4. **Resource Limits**: Set appropriate CPU/memory limits
5. **Monitoring**: Enable Prometheus ServiceMonitor and Grafana dashboards
6. **Backups**: Configure PostgreSQL backup schedules

## Monitoring & Observability

### Prometheus Metrics

- `gateway_requests_total` - Total requests by method/endpoint/status
- `gateway_ai_requests_total` - AI requests by provider/model
- `gateway_security_events_total` - Security events by type
- `gateway_request_duration_seconds` - Request latency histogram

### Structured Logging

All requests are logged with structured JSON:
```json
{
  "event": "request_forwarded",
  "request_id": "uuid",
  "user_id": "uuid",
  "model": "gpt-4",
  "tokens_used": 150,
  "latency_ms": 245,
  "pii_detected": false,
  "injection_detected": false
}
```

### Audit Logs

Complete audit trail stored in PostgreSQL:
- Request/response metadata
- Token usage
- Security flags
- Policy decisions
- Error details

## API Documentation

Interactive API documentation is available at `/docs` (Swagger UI) and `/redoc` (ReDoc) when `DEBUG=true`.

## Development

### Running Tests

```bash
pytest tests/ -v --cov=app
```

### Code Quality

```bash
# Formatting
black app/ tests/

# Linting
ruff check app/ tests/

# Type checking
mypy app/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue on GitHub or contact the maintainers.

---

**Built with ❤️ by the Zero-Trust AI Team**

> "Trust nothing, verify everything, audit always."
