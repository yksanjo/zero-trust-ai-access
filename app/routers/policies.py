"""Policy management router."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user, Permissions, auth_manager
from app.security.policy_engine import PolicyAction, get_policy_engine
from app.models.user import User

router = APIRouter()


@router.get("/")
async def list_policies(user: User = Depends(get_current_user)):
    """List all policies."""
    engine = await get_policy_engine()
    policies = engine.get_policies()
    
    return {
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "enabled": p.enabled,
                "priority": p.priority,
                "action": p.action.value,
            }
            for p in policies
        ]
    }


@router.post("/validate")
async def validate_request(
    request_body: dict,
    user: User = Depends(get_current_user),
):
    """Validate a request against policies without sending to AI."""
    engine = await get_policy_engine()
    
    result = await engine.evaluate(
        user=user,
        request=request_body,
        context={"validation_mode": True},
    )
    
    return {
        "allowed": result.allowed,
        "action": result.action.value,
        "reason": result.reason,
        "violated_policies": result.violated_policies,
    }


@router.post("/test")
async def test_policy(
    policy_config: dict,
    test_request: dict,
    user: User = Depends(get_current_user),
):
    """Test a policy configuration against a sample request."""
    if not Permissions.can_manage_policies(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin required",
        )
    
    from app.security.policy_engine import Policy
    
    # Create temporary policy
    policy = Policy(
        id="test-policy",
        name=policy_config.get("name", "Test Policy"),
        description="Temporary test policy",
        conditions=policy_config.get("conditions", {}),
        action=PolicyAction(policy_config.get("action", "allow")),
    )
    
    # Test against request
    applies, reason = await policy.evaluate(
        user=user,
        request=test_request,
        context={},
    )
    
    return {
        "applies": applies,
        "reason": reason,
        "action": policy.action.value if applies else None,
    }


@router.get("/actions")
async def list_policy_actions(user: User = Depends(get_current_user)):
    """List available policy actions."""
    return {
        "actions": [
            {"value": a.value, "description": a.name.replace("_", " ").title()}
            for a in PolicyAction
        ]
    }
