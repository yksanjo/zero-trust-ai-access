"""User and Organization models."""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, EmailStr


class UserRole(str, Enum):
    """User roles for access control."""
    ADMIN = "admin"
    DEVELOPER = "developer"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SERVICE_ACCOUNT = "service_account"


class Organization(BaseModel):
    """Organization model."""
    
    id: UUID = Field(default_factory=uuid4)
    name: str
    slug: str
    plan: str = "free"  # free, team, enterprise
    daily_token_limit: int = 1_000_000
    features: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    settings: dict = Field(default_factory=dict)
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Acme Corp",
                "slug": "acme-corp",
                "plan": "enterprise",
                "daily_token_limit": 10000000,
            }
        }


class User(BaseModel):
    """User model with authentication details."""
    
    id: UUID = Field(default_factory=uuid4)
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.DEVELOPER
    organization_id: Optional[UUID] = None
    
    # Token budgets
    daily_token_limit: int = 100_000
    monthly_token_limit: int = 1_000_000
    
    # Rate limiting
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    
    # Security
    mfa_enabled: bool = False
    ip_allowlist: list[str] = Field(default_factory=list)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True
    is_verified: bool = False
    
    # Provider info (from OAuth2/OIDC)
    provider: str = "oauth2"
    provider_user_id: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174001",
                "email": "user@example.com",
                "username": "johndoe",
                "full_name": "John Doe",
                "role": "developer",
                "daily_token_limit": 100000,
                "is_active": True,
            }
        }


class UserTokenBudget(BaseModel):
    """User token budget status."""
    
    user_id: UUID
    daily_used: int = 0
    daily_limit: int = 100_000
    monthly_used: int = 0
    monthly_limit: int = 1_000_000
    reset_time: datetime
    
    @property
    def daily_remaining(self) -> int:
        return max(0, self.daily_limit - self.daily_used)
    
    @property
    def monthly_remaining(self) -> int:
        return max(0, self.monthly_limit - self.monthly_used)
    
    @property
    def is_exceeded(self) -> bool:
        return self.daily_used >= self.daily_limit or self.monthly_used >= self.monthly_limit


class APICredential(BaseModel):
    """API credential for service accounts."""
    
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    name: str
    api_key_prefix: str  # First 8 chars of the key for display
    scopes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    is_active: bool = True
