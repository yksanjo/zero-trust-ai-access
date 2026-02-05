"""Tests for authentication."""

import pytest
from fastapi import HTTPException

from app.auth import AuthManager
from app.models.user import User, UserRole


class TestAuthManager:
    """Test authentication manager."""
    
    @pytest.fixture
    def auth_manager(self):
        return AuthManager()
    
    @pytest.mark.asyncio
    async def test_authenticate_missing_credentials(self, auth_manager):
        with pytest.raises(HTTPException) as exc_info:
            await auth_manager.authenticate(None)
        
        assert exc_info.value.status_code == 401
    
    def test_password_hashing(self, auth_manager):
        password = "test_password"
        hashed = auth_manager.get_password_hash(password)
        
        assert auth_manager.verify_password(password, hashed)
        assert not auth_manager.verify_password("wrong_password", hashed)
    
    def test_create_access_token(self, auth_manager):
        data = {"sub": "user123", "email": "test@example.com"}
        token = auth_manager.create_access_token(data)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0


class TestPermissions:
    """Test permission helpers."""
    
    from app.auth import Permissions
    
    def test_can_access_model_admin(self):
        user = User(
            id="123e4567-e89b-12d3-a456-426614174000",
            email="admin@example.com",
            username="admin",
            role=UserRole.ADMIN,
        )
        
        assert Permissions.can_access_model(user, "gpt-4-32k")
    
    def test_can_access_model_viewer(self):
        user = User(
            id="123e4567-e89b-12d3-a456-426614174001",
            email="viewer@example.com",
            username="viewer",
            role=UserRole.VIEWER,
        )
        
        # Viewers can access standard models
        assert Permissions.can_access_model(user, "gpt-3.5-turbo")
    
    def test_can_view_audit_logs(self):
        admin = User(
            id="123e4567-e89b-12d3-a456-426614174000",
            email="admin@example.com",
            username="admin",
            role=UserRole.ADMIN,
        )
        
        analyst = User(
            id="123e4567-e89b-12d3-a456-426614174002",
            email="analyst@example.com",
            username="analyst",
            role=UserRole.ANALYST,
        )
        
        developer = User(
            id="123e4567-e89b-12d3-a456-426614174003",
            email="dev@example.com",
            username="dev",
            role=UserRole.DEVELOPER,
        )
        
        assert Permissions.can_view_audit_logs(admin)
        assert Permissions.can_view_audit_logs(analyst)
        assert not Permissions.can_view_audit_logs(developer)
