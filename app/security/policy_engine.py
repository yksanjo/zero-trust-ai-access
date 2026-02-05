"""Dynamic policy engine for AI access control."""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from uuid import UUID

import structlog

from app.config import get_settings
from app.models.user import User, UserRole

logger = structlog.get_logger()


class PolicyAction(str, Enum):
    """Actions that can be taken when a policy is triggered."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    ANONYMIZE = "anonymize"
    LOG = "log"
    QUARANTINE = "quarantine"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class PolicyResult:
    """Result of policy evaluation."""
    
    allowed: bool
    action: PolicyAction
    reason: str
    violated_policies: list[str] = field(default_factory=list)
    modified_request: Optional[dict] = None
    additional_data: dict = field(default_factory=dict)


@dataclass
class Policy:
    """Individual policy rule."""
    
    id: str
    name: str
    description: str
    enabled: bool = True
    priority: int = 100
    
    # Conditions
    conditions: dict = field(default_factory=dict)
    
    # Action
    action: PolicyAction = PolicyAction.ALLOW
    
    # Modifiers
    modify_request: Optional[Callable] = None
    
    async def evaluate(
        self,
        user: User,
        request: dict,
        context: dict,
    ) -> tuple[bool, Optional[str]]:
        """
        Evaluate if this policy applies.
        
        Returns:
            Tuple of (applies, reason)
        """
        if not self.enabled:
            return False, None
        
        # Check user role condition
        if "allowed_roles" in self.conditions:
            if user.role.value not in self.conditions["allowed_roles"]:
                return True, f"Role {user.role.value} not in allowed roles"
        
        # Check denied roles
        if "denied_roles" in self.conditions:
            if user.role.value in self.conditions["denied_roles"]:
                return True, f"Role {user.role.value} is denied"
        
        # Check model restrictions
        if "allowed_models" in self.conditions:
            model = request.get("model", "")
            allowed = self.conditions["allowed_models"]
            if model not in allowed:
                return True, f"Model {model} not in allowed models"
        
        if "denied_models" in self.conditions:
            model = request.get("model", "")
            if model in self.conditions["denied_models"]:
                return True, f"Model {model} is denied"
        
        # Check content patterns
        if "content_patterns" in self.conditions:
            content = self._extract_content(request)
            for pattern in self.conditions["content_patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    return True, f"Content matches blocked pattern: {pattern}"
        
        # Check required patterns (must be present)
        if "required_patterns" in self.conditions:
            content = self._extract_content(request)
            for pattern in self.conditions["required_patterns"]:
                if not re.search(pattern, content, re.IGNORECASE):
                    return True, f"Content missing required pattern"
        
        # Check time-based conditions
        if "allowed_hours" in self.conditions:
            from datetime import datetime
            current_hour = datetime.utcnow().hour
            if current_hour not in self.conditions["allowed_hours"]:
                return True, f"Access not allowed at hour {current_hour}"
        
        # Check IP allowlist
        if "ip_allowlist" in self.conditions:
            client_ip = context.get("client_ip", "")
            if client_ip not in self.conditions["ip_allowlist"]:
                return True, f"IP {client_ip} not in allowlist"
        
        # Check custom condition function
        if "custom_check" in self.conditions:
            custom_result = await self.conditions["custom_check"](user, request, context)
            if custom_result:
                return True, str(custom_result)
        
        return False, None
    
    def _extract_content(self, request: dict) -> str:
        """Extract searchable content from request."""
        content_parts = []
        
        # Chat messages
        if "messages" in request:
            for msg in request["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content_parts.append(str(msg["content"]))
        
        # Completion prompt
        if "prompt" in request:
            content_parts.append(str(request["prompt"]))
        
        return " ".join(content_parts)


class PolicyEngine:
    """Engine for evaluating access policies."""
    
    def __init__(self) -> None:
        self._policies: list[Policy] = []
        self._settings = get_settings()
        self._init_default_policies()
    
    def _init_default_policies(self) -> None:
        """Initialize default security policies."""
        
        # Block high-risk models for non-admins
        self.add_policy(Policy(
            id="restrict-high-risk-models",
            name="Restrict High-Risk Models",
            description="Block access to high-risk models for non-admin users",
            priority=10,
            conditions={
                "denied_roles": [UserRole.VIEWER.value],
                "denied_models": ["gpt-4-32k", "claude-3-opus"],  # Expensive models
            },
            action=PolicyAction.BLOCK,
        ))
        
        # Require approval for code generation by analysts
        self.add_policy(Policy(
            id="code-gen-approval",
            name="Code Generation Approval",
            description="Require approval for code generation by analysts",
            priority=20,
            conditions={
                "allowed_roles": [UserRole.ANALYST.value],
                "content_patterns": [
                    r"\b(write|generate|create)\s+(code|script|program)",
                    r"\b(python|javascript|java|cpp|c\+\+|rust|go)\s+(code|script)",
                ],
            },
            action=PolicyAction.REQUIRE_APPROVAL,
        ))
        
        # Block requests with blocked patterns
        self.add_policy(Policy(
            id="blocked-patterns",
            name="Blocked Content Patterns",
            description="Block requests matching blocked patterns",
            priority=5,
            conditions={
                "content_patterns": [
                    re.escape(p) for p in self._settings.blocked_patterns_list if p
                ],
            },
            action=PolicyAction.BLOCK,
        ))
        
        # Anonymize PII for viewer role
        self.add_policy(Policy(
            id="anonymize-viewer-pii",
            name="Anonymize Viewer PII",
            description="Always anonymize PII for viewer role",
            priority=30,
            conditions={
                "allowed_roles": [UserRole.VIEWER.value],
            },
            action=PolicyAction.ANONYMIZE,
        ))
        
        # Log all service account requests
        self.add_policy(Policy(
            id="log-service-accounts",
            name="Log Service Account Requests",
            description="Enhanced logging for service account requests",
            priority=15,
            conditions={
                "allowed_roles": [UserRole.SERVICE_ACCOUNT.value],
            },
            action=PolicyAction.LOG,
        ))
    
    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine."""
        self._policies.append(policy)
        # Sort by priority
        self._policies.sort(key=lambda p: p.priority)
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID."""
        original_len = len(self._policies)
        self._policies = [p for p in self._policies if p.id != policy_id]
        return len(self._policies) < original_len
    
    def get_policies(self) -> list[Policy]:
        """Get all policies."""
        return self._policies.copy()
    
    async def evaluate(
        self,
        user: User,
        request: dict,
        context: Optional[dict] = None,
    ) -> PolicyResult:
        """
        Evaluate all policies against a request.
        
        Returns:
            PolicyResult with evaluation outcome
        """
        context = context or {}
        violated_policies = []
        highest_action = PolicyAction.ALLOW
        reasons = []
        modified_request = None
        
        for policy in self._policies:
            applies, reason = await policy.evaluate(user, request, context)
            
            if applies:
                violated_policies.append(policy.id)
                reasons.append(f"{policy.name}: {reason}")
                
                # Track highest severity action
                action_priority = {
                    PolicyAction.ALLOW: 0,
                    PolicyAction.LOG: 1,
                    PolicyAction.WARN: 2,
                    PolicyAction.ANONYMIZE: 3,
                    PolicyAction.QUARANTINE: 4,
                    PolicyAction.REQUIRE_APPROVAL: 5,
                    PolicyAction.BLOCK: 6,
                }
                
                if action_priority.get(policy.action, 0) > action_priority.get(highest_action, 0):
                    highest_action = policy.action
                
                # Apply request modifications
                if policy.modify_request:
                    modified_request = policy.modify_request(request.copy())
        
        allowed = highest_action not in [PolicyAction.BLOCK]
        
        return PolicyResult(
            allowed=allowed,
            action=highest_action,
            reason="; ".join(reasons) if reasons else "All policies passed",
            violated_policies=violated_policies,
            modified_request=modified_request,
        )
    
    async def evaluate_with_security_context(
        self,
        user: User,
        request: dict,
        pii_detected: bool,
        pii_types: list[str],
        injection_detected: bool,
        injection_confidence: float,
        context: Optional[dict] = None,
    ) -> PolicyResult:
        """
        Evaluate policies with security detection context.
        
        This combines policy rules with PII and injection detection results.
        """
        base_result = await self.evaluate(user, request, context)
        
        # Check PII policies
        if pii_detected:
            # High-risk PII always triggers anonymization
            high_risk_pii = {"CREDIT_CARD", "US_SSN", "PASSWORD", "API_KEY"}
            if any(pii in high_risk_pii for pii in pii_types):
                if base_result.action not in [PolicyAction.BLOCK]:
                    base_result.action = PolicyAction.ANONYMIZE
                    base_result.violated_policies.append("high-risk-pii-detected")
                    base_result.reason += "; High-risk PII detected, anonymization required"
        
        # Check injection policies
        if injection_detected and injection_confidence > 0.7:
            base_result.allowed = False
            base_result.action = PolicyAction.BLOCK
            base_result.violated_policies.append("prompt-injection-detected")
            base_result.reason += f"; Prompt injection detected (confidence: {injection_confidence:.2f})"
        elif injection_detected and injection_confidence > 0.5:
            if base_result.action not in [PolicyAction.BLOCK]:
                base_result.action = PolicyAction.QUARANTINE
                base_result.violated_policies.append("suspicious-prompt-detected")
        
        return base_result
    
    def create_dynamic_policy(
        self,
        name: str,
        condition_type: str,
        condition_value: Any,
        action: PolicyAction,
    ) -> Policy:
        """Create a dynamic policy programmatically."""
        
        conditions: dict[str, Any] = {}
        
        if condition_type == "model_restriction":
            conditions["denied_models"] = condition_value if isinstance(condition_value, list) else [condition_value]
        elif condition_type == "role_restriction":
            conditions["denied_roles"] = condition_value if isinstance(condition_value, list) else [condition_value]
        elif condition_type == "content_filter":
            conditions["content_patterns"] = condition_value if isinstance(condition_value, list) else [condition_value]
        elif condition_type == "time_restriction":
            conditions["allowed_hours"] = condition_value
        elif condition_type == "ip_restriction":
            conditions["ip_allowlist"] = condition_value
        
        policy = Policy(
            id=f"dynamic-{name.lower().replace(' ', '-')}",
            name=name,
            description=f"Dynamically created policy: {name}",
            priority=50,
            conditions=conditions,
            action=action,
        )
        
        return policy


# Global policy engine instance
policy_engine = PolicyEngine()


async def get_policy_engine() -> PolicyEngine:
    """Get policy engine instance."""
    return policy_engine
