"""Redis client for session state, rate limiting, and caching."""

import json
from datetime import datetime, timedelta
from typing import Optional, Any
from uuid import UUID

import redis.asyncio as redis

from app.config import get_settings
import structlog

logger = structlog.get_logger()


class RedisClient:
    """Redis client wrapper for gateway operations."""
    
    def __init__(self) -> None:
        self.client: Optional[redis.Redis] = None
        self._settings = get_settings()
    
    async def connect(self) -> None:
        """Initialize Redis connection."""
        try:
            if self._settings.redis_password:
                self.client = redis.from_url(
                    self._settings.redis_url,
                    password=self._settings.redis_password,
                    ssl=self._settings.redis_ssl,
                    decode_responses=True,
                )
            else:
                self.client = redis.from_url(
                    self._settings.redis_url,
                    decode_responses=True,
                )
            
            # Test connection
            await self.client.ping()
            logger.info("redis_connected", url=self._settings.redis_url)
        except Exception as e:
            logger.error("redis_connection_failed", error=str(e))
            raise
    
    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self.client:
            await self.client.close()
            logger.info("redis_disconnected")
    
    # Session Management
    
    async def set_session(
        self,
        session_id: str,
        data: dict,
        ttl_seconds: int = 3600,
    ) -> None:
        """Store session data."""
        if not self.client:
            return
        
        key = f"session:{session_id}"
        await self.client.setex(key, ttl_seconds, json.dumps(data))
    
    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get session data."""
        if not self.client:
            return None
        
        key = f"session:{session_id}"
        data = await self.client.get(key)
        if data:
            return json.loads(data)
        return None
    
    async def delete_session(self, session_id: str) -> None:
        """Delete session."""
        if not self.client:
            return
        
        key = f"session:{session_id}"
        await self.client.delete(key)
    
    # Rate Limiting
    
    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int, int]:
        """
        Check if request is within rate limit.
        Returns: (allowed, remaining, reset_time)
        """
        if not self.client:
            return True, limit, 0
        
        current_key = f"ratelimit:{key}:{window_seconds}"
        now = datetime.utcnow().timestamp()
        window_start = int(now // window_seconds * window_seconds)
        
        pipe = self.client.pipeline()
        pipe.zremrangebyscore(current_key, 0, now - window_seconds)
        pipe.zcard(current_key)
        pipe.zadd(current_key, {str(now): now})
        pipe.expire(current_key, window_seconds + 1)
        
        results = await pipe.execute()
        current_count = results[1]
        
        allowed = current_count < limit
        remaining = max(0, limit - current_count - 1)
        reset_time = window_start + window_seconds
        
        if not allowed:
            # Remove the added entry if over limit
            await self.client.zrem(current_key, str(now))
        
        return allowed, remaining, reset_time
    
    async def get_rate_limit_status(
        self,
        key: str,
        window_seconds: int,
    ) -> dict:
        """Get current rate limit status."""
        if not self.client:
            return {"count": 0, "limit": 0, "remaining": 0}
        
        current_key = f"ratelimit:{key}:{window_seconds}"
        now = datetime.utcnow().timestamp()
        
        await self.client.zremrangebyscore(current_key, 0, now - window_seconds)
        count = await self.client.zcard(current_key)
        
        return {
            "count": count,
            "window_start": int(now // window_seconds * window_seconds),
        }
    
    # Token Budgeting
    
    async def get_token_usage(self, user_id: UUID, period: str = "daily") -> int:
        """Get token usage for a user in the current period."""
        if not self.client:
            return 0
        
        today = datetime.utcnow().strftime("%Y-%m-%d")
        key = f"tokens:{period}:{user_id}:{today}"
        
        usage = await self.client.get(key)
        return int(usage) if usage else 0
    
    async def increment_token_usage(
        self,
        user_id: UUID,
        tokens: int,
        period: str = "daily",
        ttl_hours: int = 48,
    ) -> int:
        """Increment token usage for a user. Returns new total."""
        if not self.client:
            return tokens
        
        today = datetime.utcnow().strftime("%Y-%m-%d")
        key = f"tokens:{period}:{user_id}:{today}"
        
        new_usage = await self.client.incrby(key, tokens)
        await self.client.expire(key, ttl_hours * 3600)
        
        return new_usage
    
    async def check_token_budget(
        self,
        user_id: UUID,
        requested_tokens: int,
        limit: int,
    ) -> tuple[bool, int]:
        """
        Check if token budget allows the request.
        Returns: (allowed, remaining)
        """
        current_usage = await self.get_token_usage(user_id, "daily")
        remaining = limit - current_usage
        
        allowed = (current_usage + requested_tokens) <= limit
        return allowed, remaining
    
    # Response Caching
    
    async def get_cached_response(self, cache_key: str) -> Optional[dict]:
        """Get cached response."""
        if not self.client:
            return None
        
        key = f"cache:response:{cache_key}"
        data = await self.client.get(key)
        if data:
            return json.loads(data)
        return None
    
    async def cache_response(
        self,
        cache_key: str,
        response: dict,
        ttl_seconds: int = 300,
    ) -> None:
        """Cache a response."""
        if not self.client:
            return
        
        key = f"cache:response:{cache_key}"
        await self.client.setex(key, ttl_seconds, json.dumps(response))
    
    async def invalidate_cache_pattern(self, pattern: str) -> int:
        """Invalidate cache keys matching pattern."""
        if not self.client:
            return 0
        
        keys = await self.client.keys(f"cache:response:{pattern}")
        if keys:
            return await self.client.delete(*keys)
        return 0
    
    # Blocklist/Allowlist
    
    async def is_blocked_ip(self, ip: str) -> bool:
        """Check if IP is blocked."""
        if not self.client:
            return False
        
        return await self.client.sismember("blocklist:ips", ip)
    
    async def block_ip(self, ip: str, ttl_seconds: Optional[int] = None) -> None:
        """Block an IP address."""
        if not self.client:
            return
        
        if ttl_seconds:
            await self.client.setex(f"blocklist:ip:{ip}", ttl_seconds, "1")
        else:
            await self.client.sadd("blocklist:ips", ip)
    
    async def is_blocked_api_key(self, api_key_hash: str) -> bool:
        """Check if API key is blocked."""
        if not self.client:
            return False
        
        return await self.client.sismember("blocklist:api_keys", api_key_hash)
    
    # Metrics and Analytics
    
    async def increment_counter(
        self,
        metric_name: str,
        value: int = 1,
        tags: Optional[dict] = None,
    ) -> None:
        """Increment a metric counter."""
        if not self.client:
            return
        
        key = f"metrics:{metric_name}"
        if tags:
            tag_str = ":".join(f"{k}={v}" for k, v in sorted(tags.items()))
            key = f"{key}:{tag_str}"
        
        today = datetime.utcnow().strftime("%Y-%m-%d")
        await self.client.hincrby(f"{key}:{today}", "count", value)
        await self.client.expire(f"{key}:{today}", 86400 * 30)  # Keep 30 days
    
    async def record_latency(
        self,
        metric_name: str,
        latency_ms: float,
        tags: Optional[dict] = None,
    ) -> None:
        """Record latency metric."""
        if not self.client:
            return
        
        key = f"metrics:latency:{metric_name}"
        if tags:
            tag_str = ":".join(f"{k}={v}" for k, v in sorted(tags.items()))
            key = f"{key}:{tag_str}"
        
        today = datetime.utcnow().strftime("%Y-%m-%d")
        day_key = f"{key}:{today}"
        
        pipe = self.client.pipeline()
        pipe.lpush(f"{day_key}:values", latency_ms)
        pipe.ltrim(f"{day_key}:values", 0, 999)  # Keep last 1000 values
        pipe.expire(day_key, 86400 * 7)  # Keep 7 days
        await pipe.execute()
    
    # Gateway Health
    
    async def set_gateway_health(self, component: str, healthy: bool, info: Optional[dict] = None) -> None:
        """Set health status for a component."""
        if not self.client:
            return
        
        data = {
            "healthy": healthy,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if info:
            data.update(info)
        
        await self.client.setex(
            f"health:{component}",
            60,  # 60 second TTL
            json.dumps(data)
        )
    
    async def get_gateway_health(self) -> dict:
        """Get health status for all components."""
        if not self.client:
            return {}
        
        keys = await self.client.keys("health:*")
        if not keys:
            return {}
        
        health_data = {}
        for key in keys:
            component = key.split(":", 1)[1]
            data = await self.client.get(key)
            if data:
                health_data[component] = json.loads(data)
        
        return health_data


# Global Redis instance
redis_client = RedisClient()


async def get_redis() -> RedisClient:
    """Get Redis client instance."""
    return redis_client
