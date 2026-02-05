"""Admin router for gateway management."""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import get_current_user, Permissions
from app.database import get_database
from app.models.responses import GatewayStats
from app.models.user import User, UserRole
from app.redis_client import get_redis

router = APIRouter()


@router.get("/stats", response_model=GatewayStats)
async def get_stats(
    user: User = Depends(get_current_user),
    hours: int = Query(default=24, ge=1, le=168),
):
    """Get gateway statistics."""
    if not Permissions.can_view_audit_logs(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    
    db = await get_database()
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    summary = await db.get_audit_summary(
        start_time=start_time,
        end_time=end_time,
        organization_id=user.organization_id,
    )
    
    return GatewayStats(
        total_events=summary.total_events,
        events_by_type=summary.events_by_type,
        events_by_provider=summary.events_by_provider,
        unique_users=summary.unique_users,
        total_tokens_used=summary.total_tokens,
        estimated_cost_usd=summary.estimated_cost,
        security_incidents=summary.security_incidents,
        period_start=start_time,
        period_end=end_time,
    )


@router.get("/users/{user_id}/usage")
async def get_user_usage(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
):
    """Get token usage for a specific user."""
    # Users can only view their own usage, admins can view any
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only view your own usage",
        )
    
    db = await get_database()
    redis = await get_redis()
    
    # Get today's usage from Redis
    daily_tokens = await redis.get_token_usage(user_id, "daily")
    
    # Get from database for persistence
    db_usage = await db.get_token_usage(user_id)
    
    return {
        "user_id": str(user_id),
        "daily_tokens": daily_tokens,
        "db_recorded_tokens": db_usage.get("total_tokens", 0),
        "request_count": db_usage.get("request_count", 0),
        "estimated_cost": db_usage.get("estimated_cost_usd", 0),
    }


@router.post("/users/{user_id}/reset-budget")
async def reset_user_budget(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
):
    """Reset token budget for a user."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin required",
        )
    
    redis = await get_redis()
    # Reset by deleting the counter (will be recreated on next use)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = f"tokens:daily:{user_id}:{today}"
    await redis.client.delete(key)
    
    return {"message": "Budget reset", "user_id": str(user_id)}


@router.get("/health/detailed")
async def detailed_health(user: User = Depends(get_current_user)):
    """Get detailed health status of all components."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin required",
        )
    
    redis = await get_redis()
    health = await redis.get_gateway_health()
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "components": health,
        "overall": "healthy" if all(
            h.get("healthy", False) for h in health.values()
        ) else "degraded",
    }
