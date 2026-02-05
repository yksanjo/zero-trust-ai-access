"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )
    
    # Application Settings
    app_name: str = "Zero-Trust AI Access Gateway"
    debug: bool = False
    log_level: str = "INFO"
    secret_key: str = "change-me-in-production"
    
    # Server Settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    # Database Settings
    database_url: str = "postgresql://postgres:postgres@localhost:5432/zerotrust_ai"
    database_pool_size: int = 20
    database_max_overflow: int = 30
    
    # Redis Settings
    redis_url: str = "redis://localhost:6379/0"
    redis_password: Optional[str] = None
    redis_ssl: bool = False
    
    # OAuth2/OIDC Settings
    oauth2_provider_url: str = "https://auth.example.com"
    oauth2_client_id: str = ""
    oauth2_client_secret: str = ""
    oauth2_audience: str = "ai-api-gateway"
    oidc_discovery_url: Optional[str] = None
    
    # JWT Settings
    jwt_algorithm: str = "RS256"
    jwt_public_key_path: Optional[str] = None
    jwt_issuer: str = "https://auth.example.com"
    jwt_audience: str = "ai-api-gateway"
    
    # AI Provider Settings
    openai_api_key: Optional[str] = None
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_api_key: Optional[str] = None
    anthropic_base_url: str = "https://api.anthropic.com"
    local_llm_url: Optional[str] = None
    local_llm_api_key: Optional[str] = None
    
    # Rate Limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_hour: int = 1000
    rate_limit_window_seconds: int = 60
    
    # Token Budgeting
    default_user_daily_token_limit: int = 100_000
    default_org_daily_token_limit: int = 1_000_000
    token_budget_reset_hour: int = 0
    
    # Security Settings
    pii_detection_enabled: bool = True
    prompt_injection_detection_enabled: bool = True
    max_prompt_length: int = 16000
    blocked_patterns: str = "ignore previous instructions,system prompt"
    
    # Audit Logging
    audit_log_retention_days: int = 90
    audit_log_level: str = "INFO"
    
    @property
    def blocked_patterns_list(self) -> list[str]:
        """Return blocked patterns as a list."""
        return [p.strip().lower() for p in self.blocked_patterns.split(",") if p.strip()]
    
    @property
    def jwt_public_key(self) -> Optional[str]:
        """Load JWT public key from file if path is configured."""
        if self.jwt_public_key_path and Path(self.jwt_public_key_path).exists():
            return Path(self.jwt_public_key_path).read_text()
        return None


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
