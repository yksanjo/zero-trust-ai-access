"""Request models for AI gateway."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class ModelProvider(str, Enum):
    """Supported AI model providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"
    AZURE = "azure"


class AIRequest(BaseModel):
    """Base AI request model."""
    
    request_id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    organization_id: Optional[UUID] = None
    
    provider: ModelProvider = ModelProvider.OPENAI
    model: str = "gpt-4"
    
    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Request context for policy evaluation
    context: dict = Field(default_factory=dict)


class ChatMessage(BaseModel):
    """Chat message for completion requests."""
    
    role: str = Field(..., description="Role: system, user, assistant, or tool")
    content: str = Field(..., description="Message content")
    name: Optional[str] = None
    tool_calls: Optional[list[dict]] = None
    tool_call_id: Optional[str] = None


class ChatCompletionRequest(AIRequest):
    """OpenAI-compatible chat completion request."""
    
    messages: list[ChatMessage]
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=None, ge=1)
    top_p: float = Field(default=1.0, ge=0.0, le=1.0)
    frequency_penalty: float = Field(default=0.0, ge=-2.0, le=2.0)
    presence_penalty: float = Field(default=0.0, ge=-2.0, le=2.0)
    stream: bool = False
    stop: Optional[list[str]] = None
    tools: Optional[list[dict]] = None
    tool_choice: Optional[str] = None
    response_format: Optional[dict] = None
    seed: Optional[int] = None
    
    @field_validator("messages")
    @classmethod
    def validate_messages(cls, v: list[ChatMessage]) -> list[ChatMessage]:
        if not v:
            raise ValueError("At least one message is required")
        return v


class CompletionRequest(AIRequest):
    """Text completion request (legacy)."""
    
    prompt: str
    suffix: Optional[str] = None
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=16, ge=1)
    top_p: float = Field(default=1.0, ge=0.0, le=1.0)
    frequency_penalty: float = Field(default=0.0, ge=-2.0, le=2.0)
    presence_penalty: float = Field(default=0.0, ge=-2.0, le=2.0)
    stream: bool = False
    stop: Optional[list[str]] = None


class EmbeddingRequest(AIRequest):
    """Embedding request."""
    
    input: str | list[str]
    model: str = "text-embedding-3-small"
    encoding_format: str = "float"
    dimensions: Optional[int] = None
    
    @field_validator("input")
    @classmethod
    def validate_input(cls, v: str | list[str]) -> str | list[str]:
        if isinstance(v, list) and len(v) > 2048:
            raise ValueError("Maximum 2048 inputs allowed per request")
        return v


class ImageGenerationRequest(AIRequest):
    """Image generation request (DALL-E, etc.)."""
    
    prompt: str
    size: str = "1024x1024"
    quality: str = "standard"
    n: int = Field(default=1, ge=1, le=10)
    style: Optional[str] = None
    response_format: str = "url"


class ModerationRequest(BaseModel):
    """Content moderation request."""
    
    input: str
    model: str = "text-moderation-latest"


class PolicyCheckRequest(BaseModel):
    """Request for policy evaluation without making AI call."""
    
    prompt: str
    user_context: dict = Field(default_factory=dict)
    required_policies: list[str] = Field(default_factory=list)
