"""AI Gateway for proxying requests to AI providers with security controls."""

import hashlib
import json
import time
from datetime import datetime
from typing import AsyncGenerator, Optional
from uuid import UUID, uuid4

import httpx
import structlog
from fastapi import HTTPException, Request, status

from app.config import get_settings
from app.database import Database, get_database
from app.models.requests import ChatCompletionRequest, ModelProvider
from app.models.responses import (
    AIResponse,
    ChatCompletionResponse,
    ErrorResponse,
    TokenUsage,
)
from app.models.audit import (
    AuditLogEntry,
    AuditEventType,
    RequestMetrics,
    SecurityFlags,
)
from app.models.user import User
from app.redis_client import RedisClient, get_redis
from app.security.pii_detector import PIIDetector, get_pii_detector
from app.security.prompt_injection_detector import (
    PromptInjectionDetector,
    get_injection_detector,
)
from app.security.policy_engine import PolicyEngine, get_policy_engine

logger = structlog.get_logger()


class AIGateway:
    """Zero-Trust AI Gateway with security controls."""
    
    # Cost per 1K tokens (approximate)
    COST_RATES = {
        "gpt-4": {"prompt": 0.03, "completion": 0.06},
        "gpt-4-turbo": {"prompt": 0.01, "completion": 0.03},
        "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
        "claude-3-opus": {"prompt": 0.015, "completion": 0.075},
        "claude-3-sonnet": {"prompt": 0.003, "completion": 0.015},
        "claude-3-haiku": {"prompt": 0.00025, "completion": 0.00125},
    }
    
    def __init__(
        self,
        db: Database,
        redis: RedisClient,
        pii_detector: PIIDetector,
        injection_detector: PromptInjectionDetector,
        policy_engine: PolicyEngine,
    ) -> None:
        self.db = db
        self.redis = redis
        self.pii_detector = pii_detector
        self.injection_detector = injection_detector
        self.policy_engine = policy_engine
        self._settings = get_settings()
        
        # HTTP client for upstream requests
        self._http_client: Optional[httpx.AsyncClient] = None
    
    async def initialize(self) -> None:
        """Initialize gateway components."""
        timeout = httpx.Timeout(60.0, connect=10.0)
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        
        self._http_client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            http2=True,
        )
        
        await self.pii_detector.initialize()
        logger.info("ai_gateway_initialized")
    
    async def shutdown(self) -> None:
        """Shutdown gateway components."""
        if self._http_client:
            await self._http_client.aclose()
        logger.info("ai_gateway_shutdown")
    
    async def process_chat_completion(
        self,
        request: Request,
        user: User,
        body: dict,
    ) -> ChatCompletionResponse:
        """
        Process a chat completion request with full security pipeline.
        """
        request_id = uuid4()
        start_time = time.time()
        
        # Initialize audit log
        audit_entry = AuditLogEntry(
            event_type=AuditEventType.REQUEST_RECEIVED,
            request_id=request_id,
            user_id=user.id,
            organization_id=user.organization_id,
            http_method="POST",
            path="/v1/chat/completions",
            client_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent"),
            provider=self._get_provider(body.get("model", "gpt-4")),
            model=body.get("model", "gpt-4"),
        )
        
        try:
            # 1. Rate Limiting Check
            await self._check_rate_limits(user, audit_entry)
            
            # 2. Token Budget Check
            estimated_tokens = self._estimate_tokens(body)
            await self._check_token_budget(user, estimated_tokens, audit_entry)
            
            # 3. Security Scanning
            messages = body.get("messages", [])
            
            # PII Detection
            pii_start = time.time()
            pii_result = await self.pii_detector.detect_in_messages(
                messages,
                anonymize=True,
            )
            pii_latency = (time.time() - pii_start) * 1000
            
            # Prompt Injection Detection
            injection_start = time.time()
            injection_result = await self.injection_detector.detect_in_messages(messages)
            injection_latency = (time.time() - injection_start) * 1000
            
            # Update audit entry with security flags
            audit_entry.security_flags = SecurityFlags(
                pii_detected=pii_result[0],
                pii_types_detected=pii_result[2],
                prompt_injection_detected=injection_result.is_injection,
                injection_confidence=injection_result.confidence,
            )
            
            # 4. Policy Evaluation
            policy_result = await self.policy_engine.evaluate_with_security_context(
                user=user,
                request=body,
                pii_detected=pii_result[0],
                pii_types=pii_result[2],
                injection_detected=injection_result.is_injection,
                injection_confidence=injection_result.confidence,
                context={"client_ip": audit_entry.client_ip},
            )
            
            audit_entry.event_type = AuditEventType.POLICY_EVALUATION
            
            if not policy_result.allowed:
                audit_entry.event_type = AuditEventType.POLICY_VIOLATION
                audit_entry.response_status_code = 403
                audit_entry.error_code = "POLICY_VIOLATION"
                audit_entry.error_message = policy_result.reason
                await self.db.save_audit_log(audit_entry)
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "Policy violation",
                        "reason": policy_result.reason,
                        "request_id": str(request_id),
                    },
                )
            
            # 5. Apply PII Anonymization if needed
            processed_body = body.copy()
            if pii_result[0] and policy_result.action.value in ["anonymize", "quarantine"]:
                processed_body["messages"] = pii_result[1]
                audit_entry.event_type = AuditEventType.PII_ANONYMIZED
            
            # 6. Check Cache
            cache_start = time.time()
            cache_key = self._generate_cache_key(processed_body)
            cached_response = await self.redis.get_cached_response(cache_key)
            cache_latency = (time.time() - cache_start) * 1000
            
            if cached_response:
                audit_entry.event_type = AuditEventType.RESPONSE_CACHED
                audit_entry.metrics = RequestMetrics(
                    total_latency_ms=(time.time() - start_time) * 1000,
                    cache_lookup_latency_ms=cache_latency,
                )
                await self.db.save_audit_log(audit_entry)
                
                return ChatCompletionResponse(**cached_response)
            
            # 7. Forward to Provider
            audit_entry.event_type = AuditEventType.REQUEST_FORWARDED
            upstream_start = time.time()
            
            response_data = await self._forward_to_provider(
                provider=audit_entry.provider,
                endpoint="/v1/chat/completions",
                body=processed_body,
            )
            
            upstream_latency = (time.time() - upstream_start) * 1000
            
            # 8. Process Response
            response = ChatCompletionResponse(
                **response_data,
                gateway_request_id=request_id,
            )
            
            # 9. Update Token Usage
            tokens_used = response.usage.total_tokens
            await self.redis.increment_token_usage(user.id, tokens_used)
            await self.db.update_token_usage(
                user_id=user.id,
                organization_id=user.organization_id,
                tokens=tokens_used,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                cost_usd=self._calculate_cost(response.model, response.usage),
            )
            
            # 10. Cache Response (if appropriate)
            if not body.get("stream", False):
                await self.redis.cache_response(
                    cache_key,
                    response.model_dump(),
                    ttl_seconds=300,
                )
            
            # 11. Final Audit Logging
            total_latency = (time.time() - start_time) * 1000
            audit_entry.event_type = AuditEventType.RESPONSE_RECEIVED
            audit_entry.metrics = RequestMetrics(
                request_size_bytes=len(json.dumps(body)),
                response_size_bytes=len(json.dumps(response_data)),
                total_latency_ms=total_latency,
                auth_latency_ms=0,  # Already done by middleware
                policy_latency_ms=0,  # Included in total
                pii_scan_latency_ms=pii_latency,
                cache_lookup_latency_ms=cache_latency,
                upstream_latency_ms=upstream_latency,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=tokens_used,
                estimated_cost_usd=self._calculate_cost(response.model, response.usage),
            )
            await self.db.save_audit_log(audit_entry)
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("gateway_error", error=str(e), request_id=str(request_id))
            
            audit_entry.event_type = AuditEventType.ERROR_OCCURRED
            audit_entry.response_status_code = 500
            audit_entry.error_code = "INTERNAL_ERROR"
            audit_entry.error_message = str(e)
            await self.db.save_audit_log(audit_entry)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "Internal gateway error",
                    "request_id": str(request_id),
                },
            )
    
    async def _check_rate_limits(
        self,
        user: User,
        audit_entry: AuditLogEntry,
    ) -> None:
        """Check rate limits for the user."""
        # Per-minute limit
        allowed, remaining, reset = await self.redis.check_rate_limit(
            key=f"user:{user.id}",
            limit=user.requests_per_minute,
            window_seconds=60,
        )
        
        if not allowed:
            audit_entry.event_type = AuditEventType.RATE_LIMIT_EXCEEDED
            audit_entry.response_status_code = 429
            audit_entry.error_code = "RATE_LIMIT_EXCEEDED"
            await self.db.save_audit_log(audit_entry)
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Rate limit exceeded",
                    "retry_after": reset - int(datetime.utcnow().timestamp()),
                },
                headers={"Retry-After": str(reset - int(datetime.utcnow().timestamp()))},
            )
    
    async def _check_token_budget(
        self,
        user: User,
        estimated_tokens: int,
        audit_entry: AuditLogEntry,
    ) -> None:
        """Check if user has sufficient token budget."""
        allowed, remaining = await self.redis.check_token_budget(
            user_id=user.id,
            requested_tokens=estimated_tokens,
            limit=user.daily_token_limit,
        )
        
        audit_entry.event_type = AuditEventType.TOKEN_BUDGET_CHECK
        
        if not allowed:
            audit_entry.event_type = AuditEventType.TOKEN_BUDGET_EXCEEDED
            audit_entry.response_status_code = 429
            audit_entry.error_code = "TOKEN_BUDGET_EXCEEDED"
            await self.db.save_audit_log(audit_entry)
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Daily token budget exceeded",
                    "remaining_tokens": remaining,
                    "daily_limit": user.daily_token_limit,
                },
            )
    
    async def _forward_to_provider(
        self,
        provider: str,
        endpoint: str,
        body: dict,
    ) -> dict:
        """Forward request to AI provider."""
        if not self._http_client:
            raise RuntimeError("Gateway not initialized")
        
        # Determine base URL and headers
        if provider == ModelProvider.OPENAI.value:
            base_url = self._settings.openai_base_url
            headers = {
                "Authorization": f"Bearer {self._settings.openai_api_key}",
                "Content-Type": "application/json",
            }
        elif provider == ModelProvider.ANTHROPIC.value:
            base_url = self._settings.anthropic_base_url
            headers = {
                "x-api-key": self._settings.anthropic_api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            }
        elif provider == ModelProvider.LOCAL.value:
            base_url = self._settings.local_llm_url or "http://localhost:11434/v1"
            headers = {
                "Content-Type": "application/json",
            }
            if self._settings.local_llm_api_key:
                headers["Authorization"] = f"Bearer {self._settings.local_llm_api_key}"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown provider: {provider}",
            )
        
        # Make request
        url = f"{base_url}{endpoint}"
        
        try:
            response = await self._http_client.post(
                url,
                headers=headers,
                json=body,
            )
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            logger.error(
                "provider_http_error",
                status_code=e.response.status_code,
                response=e.response.text,
            )
            raise HTTPException(
                status_code=e.response.status_code,
                detail={
                    "error": "Provider error",
                    "provider_response": e.response.text,
                },
            )
        except httpx.RequestError as e:
            logger.error("provider_request_error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI provider unavailable",
            )
    
    def _get_provider(self, model: str) -> str:
        """Determine provider from model name."""
        model_lower = model.lower()
        
        if model_lower.startswith("gpt") or model_lower.startswith("text-"):
            return ModelProvider.OPENAI.value
        elif model_lower.startswith("claude"):
            return ModelProvider.ANTHROPIC.value
        elif self._settings.local_llm_url:
            return ModelProvider.LOCAL.value
        
        return ModelProvider.OPENAI.value  # Default
    
    def _estimate_tokens(self, body: dict) -> int:
        """Rough estimation of token count."""
        # Simple estimation: ~4 chars per token
        total_chars = 0
        
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                total_chars += len(content)
        
        # Add overhead for message format
        message_count = len(body.get("messages", []))
        overhead = message_count * 4  # ~4 tokens per message
        
        return (total_chars // 4) + overhead + 100  # Buffer
    
    def _calculate_cost(self, model: str, usage: TokenUsage) -> float:
        """Calculate approximate cost in USD."""
        # Find matching cost rate
        rate = None
        for prefix, costs in self.COST_RATES.items():
            if model.startswith(prefix):
                rate = costs
                break
        
        if not rate:
            return 0.0
        
        prompt_cost = (usage.prompt_tokens / 1000) * rate["prompt"]
        completion_cost = (usage.completion_tokens / 1000) * rate["completion"]
        
        return round(prompt_cost + completion_cost, 6)
    
    def _generate_cache_key(self, body: dict) -> str:
        """Generate cache key for request."""
        # Remove non-deterministic fields
        cache_body = {
            "model": body.get("model"),
            "messages": body.get("messages"),
            "temperature": body.get("temperature", 0.7),
            "max_tokens": body.get("max_tokens"),
            "top_p": body.get("top_p", 1.0),
        }
        
        body_json = json.dumps(cache_body, sort_keys=True)
        return hashlib.sha256(body_json.encode()).hexdigest()
    
    async def get_gateway_stats(self) -> dict:
        """Get gateway statistics."""
        # This would typically aggregate from database
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
        }


# Global gateway instance
_gateway: Optional[AIGateway] = None


async def get_gateway() -> AIGateway:
    """Get or create gateway instance."""
    global _gateway
    if _gateway is None:
        _gateway = AIGateway(
            db=await get_database(),
            redis=await get_redis(),
            pii_detector=await get_pii_detector(),
            injection_detector=await get_injection_detector(),
            policy_engine=await get_policy_engine(),
        )
        await _gateway.initialize()
    return _gateway
