"""Audit log models."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    """Types of audit events."""
    REQUEST_RECEIVED = "request_received"
    AUTHENTICATION_ATTEMPT = "authentication_attempt"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_CHECK = "authorization_check"
    RATE_LIMIT_CHECK = "rate_limit_check"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    POLICY_EVALUATION = "policy_evaluation"
    POLICY_VIOLATION = "policy_violation"
    PII_DETECTED = "pii_detected"
    PII_ANONYMIZED = "pii_anonymized"
    PROMPT_INJECTION_DETECTED = "prompt_injection_detected"
    REQUEST_FORWARDED = "request_forwarded"
    RESPONSE_RECEIVED = "response_received"
    RESPONSE_CACHED = "response_cached"
    TOKEN_BUDGET_CHECK = "token_budget_check"
    TOKEN_BUDGET_EXCEEDED = "token_budget_exceeded"
    ERROR_OCCURRED = "error_occurred"


class RequestMetrics(BaseModel):
    """Request performance metrics."""
    
    request_size_bytes: int = 0
    response_size_bytes: int = 0
    total_latency_ms: float = 0.0
    
    # Breakdown
    auth_latency_ms: float = 0.0
    policy_latency_ms: float = 0.0
    pii_scan_latency_ms: float = 0.0
    cache_lookup_latency_ms: float = 0.0
    upstream_latency_ms: float = 0.0
    
    # Token usage
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class SecurityFlags(BaseModel):
    """Security flags for the request."""
    
    pii_detected: bool = False
    pii_types_detected: list[str] = Field(default_factory=list)
    prompt_injection_detected: bool = False
    injection_confidence: float = 0.0
    blocked_by_policy: bool = False
    violating_policies: list[str] = Field(default_factory=list)
    ip_reputation_score: float = 0.0
    anomaly_score: float = 0.0


class AuditLogEntry(BaseModel):
    """Complete audit log entry."""
    
    id: UUID = Field(default_factory=uuid4)
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Request identification
    request_id: UUID
    trace_id: Optional[str] = None
    
    # User information
    user_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None
    api_key_id: Optional[UUID] = None
    
    # Request details
    http_method: str
    path: str
    query_params: dict = Field(default_factory=dict)
    client_ip: str
    user_agent: Optional[str] = None
    
    # AI request specifics
    provider: Optional[str] = None
    model: Optional[str] = None
    request_summary: Optional[str] = None  # Truncated/sanitized
    
    # Metrics and flags
    metrics: RequestMetrics = Field(default_factory=RequestMetrics)
    security_flags: SecurityFlags = Field(default_factory=SecurityFlags)
    
    # Response info
    response_status_code: int = 200
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    
    # Additional context
    metadata: dict = Field(default_factory=dict)
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "event_type": "request_forwarded",
                "timestamp": "2024-01-15T10:30:00Z",
                "request_id": "123e4567-e89b-12d3-a456-426614174001",
                "user_id": "123e4567-e89b-12d3-a456-426614174002",
                "organization_id": "123e4567-e89b-12d3-a456-426614174003",
                "http_method": "POST",
                "path": "/v1/chat/completions",
                "client_ip": "192.168.1.1",
                "provider": "openai",
                "model": "gpt-4",
                "response_status_code": 200,
            }
        }


class AuditQuery(BaseModel):
    """Query parameters for audit log search."""
    
    user_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None
    event_types: list[AuditEventType] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    status_codes: list[int] = Field(default_factory=list)
    security_incident: Optional[bool] = None
    
    # Pagination
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)
    
    # Sorting
    sort_by: str = "timestamp"
    sort_order: str = "desc"


class AuditSummary(BaseModel):
    """Summary statistics for audit logs."""
    
    total_events: int = 0
    events_by_type: dict[str, int] = Field(default_factory=dict)
    events_by_provider: dict[str, int] = Field(default_factory=dict)
    unique_users: int = 0
    total_tokens: int = 0
    estimated_cost: float = 0.0
    security_incidents: int = 0
    
    # Time range
    start_time: datetime
    end_time: datetime
