"""Authentication and authorization middleware."""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings
from app.models.user import User, UserRole
import structlog

logger = structlog.get_logger()

# Security setup
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory user cache (in production, use Redis)
_user_cache: dict[str, User] = {}


class AuthManager:
    """Manages authentication and authorization."""
    
    def __init__(self) -> None:
        self._settings = get_settings()
    
    async def authenticate(
        self,
        credentials: Optional[HTTPAuthorizationCredentials],
    ) -> User:
        """
        Authenticate request and return user.
        
        Supports:
        - JWT tokens (OAuth2/OIDC)
        - API keys
        """
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token = credentials.credentials
        
        # Check if it's an API key format (starts with specific prefix)
        if token.startswith("ztai_") or token.startswith("sk-"):
            return await self._authenticate_api_key(token)
        
        # Otherwise treat as JWT
        return await self._authenticate_jwt(token)
    
    async def _authenticate_jwt(self, token: str) -> User:
        """Authenticate using JWT token."""
        try:
            # Get public key for verification
            public_key = self._settings.jwt_public_key
            
            if public_key:
                # Asymmetric verification (RS256)
                payload = jwt.decode(
                    token,
                    public_key,
                    algorithms=[self._settings.jwt_algorithm],
                    audience=self._settings.jwt_audience,
                    issuer=self._settings.jwt_issuer,
                )
            else:
                # Symmetric verification (HS256) - for dev only
                payload = jwt.decode(
                    token,
                    self._settings.secret_key,
                    algorithms=["HS256"],
                    audience=self._settings.jwt_audience,
                )
            
            # Extract user info from token
            user_id = payload.get("sub")
            email = payload.get("email")
            name = payload.get("name", "")
            roles = payload.get("roles", [])
            org_id = payload.get("org_id")
            
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: missing subject",
                )
            
            # Map roles
            role = UserRole.DEVELOPER
            if "admin" in roles:
                role = UserRole.ADMIN
            elif "viewer" in roles:
                role = UserRole.VIEWER
            elif "analyst" in roles:
                role = UserRole.ANALYST
            
            # Create user object
            user = User(
                id=UUID(user_id) if self._is_valid_uuid(user_id) else self._generate_uuid_from_str(user_id),
                email=email or f"{user_id}@local",
                username=name or user_id,
                full_name=name,
                role=role,
                organization_id=UUID(org_id) if org_id and self._is_valid_uuid(org_id) else None,
                provider=self._settings.oauth2_provider_url,
                provider_user_id=user_id,
                last_login=datetime.utcnow(),
            )
            
            logger.debug("user_authenticated", user_id=str(user.id), role=user.role.value)
            return user
            
        except JWTError as e:
            logger.warning("jwt_decode_error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    async def _authenticate_api_key(self, api_key: str) -> User:
        """Authenticate using API key."""
        # In production, validate against database
        # For now, use a simple hash check
        
        # Check cache first
        if api_key in _user_cache:
            return _user_cache[api_key]
        
        # Validate API key format
        if not api_key.startswith("ztai_"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key format",
            )
        
        # Extract key ID from API key (first 16 chars after prefix)
        key_id = api_key[5:21] if len(api_key) > 21 else api_key[5:]
        
        # In production: look up in database
        # For demo: create service account user
        user = User(
            id=self._generate_uuid_from_str(key_id),
            email=f"service@{key_id}.local",
            username=f"service-{key_id}",
            role=UserRole.SERVICE_ACCOUNT,
            provider="api_key",
            provider_user_id=key_id,
            last_login=datetime.utcnow(),
        )
        
        _user_cache[api_key] = user
        logger.debug("api_key_authenticated", key_id=key_id)
        return user
    
    def create_access_token(
        self,
        data: dict,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a new JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        # Use symmetric key for token creation
        encoded_jwt = jwt.encode(
            to_encode,
            self._settings.secret_key,
            algorithm="HS256",
        )
        
        return encoded_jwt
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return pwd_context.hash(password)
    
    def _is_valid_uuid(self, value: str) -> bool:
        """Check if string is a valid UUID."""
        try:
            UUID(value)
            return True
        except ValueError:
            return False
    
    def _generate_uuid_from_str(self, value: str) -> UUID:
        """Generate a UUID from a string deterministically."""
        import hashlib
        hash_bytes = hashlib.md5(value.encode()).digest()
        return UUID(bytes=hash_bytes[:16], version=4)


# Global auth manager
auth_manager = AuthManager()


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> User:
    """Dependency to get the current authenticated user."""
    return await auth_manager.authenticate(credentials)


async def require_role(*roles: UserRole):
    """Dependency factory to require specific roles."""
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(r.value for r in roles)}",
            )
        return user
    return role_checker


# Permission helpers
class Permissions:
    """Permission check helpers."""
    
    @staticmethod
    def can_access_model(user: User, model: str) -> bool:
        """Check if user can access a specific model."""
        # Admin can access everything
        if user.role == UserRole.ADMIN:
            return True
        
        # Restrict expensive models
        expensive_models = ["gpt-4-32k", "claude-3-opus"]
        if model in expensive_models and user.role not in [UserRole.ADMIN, UserRole.DEVELOPER]:
            return False
        
        return True
    
    @staticmethod
    def can_view_audit_logs(user: User) -> bool:
        """Check if user can view audit logs."""
        return user.role in [UserRole.ADMIN, UserRole.ANALYST]
    
    @staticmethod
    def can_manage_policies(user: User) -> bool:
        """Check if user can manage policies."""
        return user.role == UserRole.ADMIN
