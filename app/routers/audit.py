"""Audit log router."""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import get_current_user, Permissions
from app.database import get_database
from app.models.audit import AuditQuery, AuditEventType
from app.models.user import User

router = APIRouter()


@router.get("/logs")
async def get_audit_logs(
    user: User = Depends(get_current_user),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_type: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """Query audit logs."""
    if not Permissions.can_view_audit_logs(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    
    db = await get_database()
    
    # Build query
    query = AuditQuery(
        user_id=user.id if user.role != "admin" else None,
        organization_id=user.organization_id,
        start_time=start_time or datetime.utcnow() - timedelta(days=7),
        end_time=end_time or datetime.utcnow(),
        limit=limit,
        offset=offset,
    )
    
    if event_type:
        try:
            query.event_types = [AuditEventType(event_type)]
        except ValueError:
            pass
    
    entries, total = await db.query_audit_logs(query)
    
    return {
        "data": [entry.model_dump() for entry in entries],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/logs/{log_id}")
async def get_audit_log(
    log_id: UUID,
    user: User = Depends(get_current_user),
):
    """Get a specific audit log entry."""
    # Implementation would fetch single log entry
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Not yet implemented",
    )


@router.get("/summary")
async def get_audit_summary(
    days: int = Query(default=7, ge=1, le=90),
    user: User = Depends(get_current_user),
):
    """Get audit summary for a time period."""
    if not Permissions.can_view_audit_logs(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    
    db = await get_database()
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
    summary = await db.get_audit_summary(
        start_time=start_time,
        end_time=end_time,
        organization_id=user.organization_id,
    )
    
    return summary.model_dump()


@router.get("/events/types")
async def get_event_types(user: User = Depends(get_current_user)):
    """List available audit event types."""
    return {
        "event_types": [
            {"value": et.value, "description": et.name.replace("_", " ").title()}
            for et in AuditEventType
        ]
    }
