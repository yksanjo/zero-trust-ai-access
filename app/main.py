"""Zero-Trust AI Access Gateway - Main Application."""

import time
from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.auth import get_current_user, require_role
from app.config import get_settings
from app.database import db as database
from app.gateway import get_gateway
from app.models.requests import ChatCompletionRequest, EmbeddingRequest
from app.models.responses import (
    ChatCompletionResponse,
    EmbeddingResponse,
    ErrorResponse,
    HealthCheck,
)
from app.models.user import User, UserRole
from app.redis_client import redis_client
from app.routers import admin, audit, policies

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Prometheus metrics
REQUEST_COUNT = Counter(
    "gateway_requests_total",
    "Total requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "gateway_request_duration_seconds",
    "Request latency",
    ["method", "endpoint"],
)
AI_REQUEST_COUNT = Counter(
    "gateway_ai_requests_total",
    "AI requests by provider",
    ["provider", "model"],
)
SECURITY_EVENTS = Counter(
    "gateway_security_events_total",
    "Security events",
    ["event_type"],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("gateway_starting")
    
    # Connect to database
    await database.connect()
    
    # Connect to Redis
    await redis_client.connect()
    
    # Initialize gateway
    gateway = await get_gateway()
    
    logger.info("gateway_started")
    
    yield
    
    # Shutdown
    logger.info("gateway_shutting_down")
    
    await gateway.shutdown()
    await redis_client.disconnect()
    await database.disconnect()
    
    logger.info("gateway_shutdown_complete")


# Create FastAPI app
settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="Zero-Trust Access Layer for AI Models - Okta for AI APIs",
    version="0.1.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware for request metrics and logging."""
    start_time = time.time()
    
    # Generate request ID
    request_id = request.headers.get("X-Request-ID", str(int(time.time() * 1000)))
    request.state.request_id = request_id
    
    # Process request
    try:
        response = await call_next(request)
    except Exception as e:
        logger.error("request_error", error=str(e), request_id=request_id)
        response = JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal server error"},
        )
    
    # Record metrics
    duration = time.time() - start_time
    endpoint = request.url.path
    method = request.method
    status_code = response.status_code
    
    REQUEST_COUNT.labels(
        method=method,
        endpoint=endpoint,
        status=status_code,
    ).inc()
    
    REQUEST_LATENCY.labels(
        method=method,
        endpoint=endpoint,
    ).observe(duration)
    
    # Add headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{duration:.3f}s"
    
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(
        "unhandled_exception",
        error=str(exc),
        request_id=getattr(request.state, "request_id", "unknown"),
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse.from_exception(
            code="INTERNAL_ERROR",
            message="An unexpected error occurred",
        ).model_dump(),
    )


# Health check endpoint
@app.get("/health", response_model=HealthCheck)
async def health_check():
    """Health check endpoint."""
    import psutil
    
    health = HealthCheck(
        database_connected=database.pool is not None,
        redis_connected=redis_client.client is not None,
        memory_usage_mb=psutil.Process().memory_info().rss / 1024 / 1024,
    )
    
    # Check AI providers
    # These would be async checks in production
    health.openai_available = bool(settings.openai_api_key)
    health.anthropic_available = bool(settings.anthropic_api_key)
    
    return health


# Metrics endpoint
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


# OpenAI-compatible API endpoints
@app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(
    request: Request,
    body: dict,
    user: User = Depends(get_current_user),
):
    """
    OpenAI-compatible chat completions endpoint.
    
    This endpoint proxies requests to AI providers with:
    - Authentication & authorization
    - Rate limiting
    - PII detection & anonymization
    - Prompt injection detection
    - Policy enforcement
    - Audit logging
    """
    gateway = await get_gateway()
    
    response = await gateway.process_chat_completion(request, user, body)
    
    AI_REQUEST_COUNT.labels(
        provider=response.provider,
        model=body.get("model", "unknown"),
    ).inc()
    
    return response


@app.post("/v1/completions")
async def completions(
    request: Request,
    body: dict,
    user: User = Depends(get_current_user),
):
    """OpenAI-compatible completions endpoint."""
    # Convert to chat format for unified processing
    if "prompt" in body:
        body["messages"] = [{"role": "user", "content": body["prompt"]}]
    
    gateway = await get_gateway()
    response = await gateway.process_chat_completion(request, user, body)
    
    return response


@app.post("/v1/embeddings", response_model=EmbeddingResponse)
async def embeddings(
    request: Request,
    body: EmbeddingRequest,
    user: User = Depends(get_current_user),
):
    """OpenAI-compatible embeddings endpoint."""
    gateway = await get_gateway()
    
    # Simplified embedding handling
    # In production, implement full security pipeline
    return EmbeddingResponse(
        data=[],
        model=body.model,
        usage={"prompt_tokens": 0, "total_tokens": 0},
    )


@app.get("/v1/models")
async def list_models(user: User = Depends(get_current_user)):
    """List available AI models."""
    models = [
        {
            "id": "gpt-4",
            "object": "model",
            "created": 1678604602,
            "owned_by": "openai",
            "permission": [],
            "root": "gpt-4",
            "parent": None,
        },
        {
            "id": "gpt-4-turbo",
            "object": "model",
            "created": 1678604602,
            "owned_by": "openai",
            "permission": [],
            "root": "gpt-4-turbo",
            "parent": None,
        },
        {
            "id": "gpt-3.5-turbo",
            "object": "model",
            "created": 1677649963,
            "owned_by": "openai",
            "permission": [],
            "root": "gpt-3.5-turbo",
            "parent": None,
        },
        {
            "id": "claude-3-opus",
            "object": "model",
            "created": 1699894440,
            "owned_by": "anthropic",
            "permission": [],
            "root": "claude-3-opus",
            "parent": None,
        },
        {
            "id": "claude-3-sonnet",
            "object": "model",
            "created": 1699894440,
            "owned_by": "anthropic",
            "permission": [],
            "root": "claude-3-sonnet",
            "parent": None,
        },
        {
            "id": "claude-3-haiku",
            "object": "model",
            "created": 1699894440,
            "owned_by": "anthropic",
            "permission": [],
            "root": "claude-3-haiku",
            "parent": None,
        },
    ]
    
    # Filter models based on user role
    if user.role == UserRole.VIEWER:
        models = [m for m in models if "gpt-3.5" in m["id"]]
    
    return {"object": "list", "data": models}


# Include routers
app.include_router(
    admin.router,
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)
app.include_router(
    audit.router,
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    policies.router,
    prefix="/policies",
    tags=["policies"],
    dependencies=[Depends(get_current_user)],
)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": settings.app_name,
        "version": "0.1.0",
        "description": "Zero-Trust Access Layer for AI Models",
        "documentation": "/docs",
        "health": "/health",
        "endpoints": {
            "chat_completions": "/v1/chat/completions",
            "completions": "/v1/completions",
            "embeddings": "/v1/embeddings",
            "models": "/v1/models",
        },
    }


def main():
    """Main entry point."""
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=1 if settings.debug else settings.workers,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
