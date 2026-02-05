"""Response models for AI gateway."""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TokenUsage(BaseModel):
    """Token usage information."""
    
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    
    # Extended metrics
    prompt_tokens_details: Optional[dict] = None
    completion_tokens_details: Optional[dict] = None


class Choice(BaseModel):
    """Completion choice."""
    
    index: int = 0
    message: dict = Field(default_factory=dict)
    finish_reason: Optional[str] = None
    logprobs: Optional[dict] = None


class ChatCompletionResponse(BaseModel):
    """OpenAI-compatible chat completion response."""
    
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[Choice]
    usage: TokenUsage
    system_fingerprint: Optional[str] = None
    
    # Gateway metadata
    gateway_request_id: Optional[UUID] = None
    provider: str = "openai"
    cached: bool = False


class CompletionResponse(BaseModel):
    """Text completion response (legacy)."""
    
    id: str
    object: str = "text_completion"
    created: int
    model: str
    choices: list[dict]
    usage: TokenUsage


class EmbeddingData(BaseModel):
    """Embedding data item."""
    
    object: str = "embedding"
    embedding: list[float]
    index: int


class EmbeddingResponse(BaseModel):
    """Embedding response."""
    
    object: str = "list"
    data: list[EmbeddingData]
    model: str
    usage: TokenUsage


class AIResponse(BaseModel):
    """Generic AI response wrapper."""
    
    success: bool = True
    request_id: UUID
    response_type: str = "chat_completion"
    
    # Response data
    data: dict = Field(default_factory=dict)
    usage: TokenUsage = Field(default_factory=TokenUsage)
    
    # Metadata
    provider: str
    model: str
    latency_ms: float = 0.0
    cached: bool = False
    
    # Security
    pii_detected: bool = False
    pii_anonymized: bool = False
    blocked_by_policy: bool = False
    block_reason: Optional[str] = None
    
    # Timestamp
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ErrorDetail(BaseModel):
    """Error detail information."""
    
    code: str
    message: str
    param: Optional[str] = None
    type: str


class ErrorResponse(BaseModel):
    """Standardized error response."""
    
    error: ErrorDetail
    request_id: Optional[UUID] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @classmethod
    def from_exception(
        cls,
        code: str,
        message: str,
        request_id: Optional[UUID] = None,
        param: Optional[str] = None,
    ) -> "ErrorResponse":
        return cls(
            error=ErrorDetail(
                code=code,
                message=message,
                param=param,
                type=code.lower().replace("_", "_"),
            ),
            request_id=request_id,
        )


class GatewayStats(BaseModel):
    """Gateway statistics."""
    
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    cached_responses: int = 0
    
    total_tokens_used: int = 0
    average_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    
    active_users: int = 0
    rate_limited_requests: int = 0
    blocked_by_policy: int = 0
    pii_detected_count: int = 0
    
    # Per-provider stats
    provider_stats: dict[str, dict] = Field(default_factory=dict)
    
    # Time window
    period_start: datetime = Field(default_factory=datetime.utcnow)
    period_end: Optional[datetime] = None


class HealthCheck(BaseModel):
    """Health check response."""
    
    status: str = "healthy"
    version: str = "0.1.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Component health
    database_connected: bool = False
    redis_connected: bool = False
    openai_available: bool = False
    anthropic_available: bool = False
    
    # Performance
    uptime_seconds: float = 0.0
    memory_usage_mb: float = 0.0
