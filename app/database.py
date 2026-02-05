"""PostgreSQL database connection and audit log storage."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

import asyncpg
from asyncpg import Pool

from app.config import get_settings
from app.models.audit import AuditLogEntry, AuditQuery, AuditSummary, AuditEventType
import structlog

logger = structlog.get_logger()


class Database:
    """PostgreSQL database manager for audit logs and user data."""
    
    def __init__(self) -> None:
        self.pool: Optional[Pool] = None
        self._settings = get_settings()
    
    async def connect(self) -> None:
        """Initialize database connection pool."""
        try:
            self.pool = await asyncpg.create_pool(
                dsn=self._settings.database_url,
                min_size=5,
                max_size=self._settings.database_pool_size,
                max_inactive_time=300,
                command_timeout=60,
            )
            logger.info("database_connected", pool_size=self._settings.database_pool_size)
            await self._init_schema()
        except Exception as e:
            logger.error("database_connection_failed", error=str(e))
            raise
    
    async def disconnect(self) -> None:
        """Close database connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("database_disconnected")
    
    async def _init_schema(self) -> None:
        """Initialize database schema."""
        async with self.pool.acquire() as conn:
            # Audit logs table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id UUID PRIMARY KEY,
                    event_type VARCHAR(50) NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    request_id UUID NOT NULL,
                    trace_id VARCHAR(100),
                    user_id UUID,
                    organization_id UUID,
                    api_key_id UUID,
                    http_method VARCHAR(10) NOT NULL,
                    path VARCHAR(500) NOT NULL,
                    query_params JSONB DEFAULT '{}',
                    client_ip INET NOT NULL,
                    user_agent VARCHAR(500),
                    provider VARCHAR(50),
                    model VARCHAR(100),
                    request_summary TEXT,
                    metrics JSONB DEFAULT '{}',
                    security_flags JSONB DEFAULT '{}',
                    response_status_code INTEGER DEFAULT 200,
                    error_message TEXT,
                    error_code VARCHAR(100),
                    metadata JSONB DEFAULT '{}'
                )
            """)
            
            # Indexes for efficient querying
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp 
                ON audit_logs(timestamp DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id 
                ON audit_logs(user_id, timestamp DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_org_id 
                ON audit_logs(organization_id, timestamp DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type 
                ON audit_logs(event_type, timestamp DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id 
                ON audit_logs(request_id)
            """)
            
            # Token usage table for efficient budgeting
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS token_usage_daily (
                    user_id UUID NOT NULL,
                    date DATE NOT NULL,
                    organization_id UUID,
                    total_tokens INTEGER DEFAULT 0,
                    prompt_tokens INTEGER DEFAULT 0,
                    completion_tokens INTEGER DEFAULT 0,
                    estimated_cost_usd DECIMAL(10, 6) DEFAULT 0,
                    request_count INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, date)
                )
            """)
            
            # Rate limit tracking table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limit_windows (
                    user_id UUID NOT NULL,
                    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
                    window_end TIMESTAMP WITH TIME ZONE NOT NULL,
                    request_count INTEGER DEFAULT 0,
                    token_count INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, window_start)
                )
            """)
            
            # Users table (caching from OIDC)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    full_name VARCHAR(255),
                    role VARCHAR(50) DEFAULT 'developer',
                    organization_id UUID,
                    daily_token_limit INTEGER DEFAULT 100000,
                    monthly_token_limit INTEGER DEFAULT 1000000,
                    requests_per_minute INTEGER DEFAULT 60,
                    requests_per_hour INTEGER DEFAULT 1000,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    ip_allowlist JSONB DEFAULT '[]',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    last_login TIMESTAMP WITH TIME ZONE,
                    is_active BOOLEAN DEFAULT TRUE,
                    is_verified BOOLEAN DEFAULT FALSE,
                    provider VARCHAR(50) DEFAULT 'oauth2',
                    provider_user_id VARCHAR(255),
                    settings JSONB DEFAULT '{}'
                )
            """)
            
            logger.info("database_schema_initialized")
    
    async def save_audit_log(self, entry: AuditLogEntry) -> None:
        """Save an audit log entry."""
        if not self.pool:
            return
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO audit_logs (
                        id, event_type, timestamp, request_id, trace_id,
                        user_id, organization_id, api_key_id, http_method, path,
                        query_params, client_ip, user_agent, provider, model,
                        request_summary, metrics, security_flags, response_status_code,
                        error_message, error_code, metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
                """,
                    entry.id, entry.event_type.value, entry.timestamp, entry.request_id,
                    entry.trace_id, entry.user_id, entry.organization_id, entry.api_key_id,
                    entry.http_method, entry.path, entry.query_params, entry.client_ip,
                    entry.user_agent, entry.provider, entry.model, entry.request_summary,
                    entry.metrics.model_dump(), entry.security_flags.model_dump(),
                    entry.response_status_code, entry.error_message, entry.error_code,
                    entry.metadata
                )
        except Exception as e:
            logger.error("failed_to_save_audit_log", error=str(e), request_id=str(entry.request_id))
    
    async def query_audit_logs(
        self, query: AuditQuery
    ) -> tuple[list[AuditLogEntry], int]:
        """Query audit logs with filters."""
        if not self.pool:
            return [], 0
        
        conditions = ["1=1"]
        params = []
        param_idx = 0
        
        if query.user_id:
            param_idx += 1
            conditions.append(f"user_id = ${param_idx}")
            params.append(query.user_id)
        
        if query.organization_id:
            param_idx += 1
            conditions.append(f"organization_id = ${param_idx}")
            params.append(query.organization_id)
        
        if query.event_types:
            param_idx += 1
            event_types = [et.value for et in query.event_types]
            conditions.append(f"event_type = ANY(${param_idx})")
            params.append(event_types)
        
        if query.start_time:
            param_idx += 1
            conditions.append(f"timestamp >= ${param_idx}")
            params.append(query.start_time)
        
        if query.end_time:
            param_idx += 1
            conditions.append(f"timestamp <= ${param_idx}")
            params.append(query.end_time)
        
        if query.provider:
            param_idx += 1
            conditions.append(f"provider = ${param_idx}")
            params.append(query.provider)
        
        if query.model:
            param_idx += 1
            conditions.append(f"model = ${param_idx}")
            params.append(query.model)
        
        if query.status_codes:
            param_idx += 1
            conditions.append(f"response_status_code = ANY(${param_idx})")
            params.append(query.status_codes)
        
        if query.security_incident is not None:
            param_idx += 1
            if query.security_incident:
                conditions.append(f"(security_flags->>'pii_detected')::boolean = ${param_idx} OR (security_flags->>'prompt_injection_detected')::boolean = ${param_idx}")
            else:
                conditions.append(f"(security_flags->>'pii_detected')::boolean = ${param_idx} AND (security_flags->>'prompt_injection_detected')::boolean = ${param_idx}")
            params.append(query.security_incident)
        
        where_clause = " AND ".join(conditions)
        
        async with self.pool.acquire() as conn:
            # Get total count
            count_query = f"SELECT COUNT(*) FROM audit_logs WHERE {where_clause}"
            total = await conn.fetchval(count_query, *params)
            
            # Get paginated results
            param_idx += 1
            offset_idx = param_idx
            params.append(query.limit)
            param_idx += 1
            limit_idx = param_idx
            params.append(query.offset)
            
            sort_order = "DESC" if query.sort_order.lower() == "desc" else "ASC"
            
            select_query = f"""
                SELECT * FROM audit_logs 
                WHERE {where_clause}
                ORDER BY {query.sort_by} {sort_order}
                LIMIT ${limit_idx} OFFSET ${offset_idx}
            """
            
            rows = await conn.fetch(select_query, *params)
            
            entries = []
            for row in rows:
                entries.append(AuditLogEntry(
                    id=row['id'],
                    event_type=AuditEventType(row['event_type']),
                    timestamp=row['timestamp'],
                    request_id=row['request_id'],
                    trace_id=row['trace_id'],
                    user_id=row['user_id'],
                    organization_id=row['organization_id'],
                    api_key_id=row['api_key_id'],
                    http_method=row['http_method'],
                    path=row['path'],
                    query_params=row['query_params'] or {},
                    client_ip=str(row['client_ip']),
                    user_agent=row['user_agent'],
                    provider=row['provider'],
                    model=row['model'],
                    request_summary=row['request_summary'],
                    metrics=row['metrics'],
                    security_flags=row['security_flags'],
                    response_status_code=row['response_status_code'],
                    error_message=row['error_message'],
                    error_code=row['error_code'],
                    metadata=row['metadata'] or {},
                ))
            
            return entries, total
    
    async def get_token_usage(
        self, user_id: UUID, date: Optional[datetime] = None
    ) -> dict:
        """Get token usage for a user on a specific date."""
        if not self.pool:
            return {"total_tokens": 0, "request_count": 0}
        
        date = date or datetime.utcnow()
        date_str = date.date()
        
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT total_tokens, prompt_tokens, completion_tokens, request_count, estimated_cost_usd
                FROM token_usage_daily
                WHERE user_id = $1 AND date = $2
                """,
                user_id, date_str
            )
            
            if row:
                return dict(row)
            return {"total_tokens": 0, "request_count": 0, "estimated_cost_usd": 0}
    
    async def update_token_usage(
        self,
        user_id: UUID,
        organization_id: Optional[UUID],
        tokens: int,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> None:
        """Update token usage for a user."""
        if not self.pool:
            return
        
        today = datetime.utcnow().date()
        
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO token_usage_daily 
                (user_id, date, organization_id, total_tokens, prompt_tokens, completion_tokens, estimated_cost_usd, request_count)
                VALUES ($1, $2, $3, $4, $5, $6, $7, 1)
                ON CONFLICT (user_id, date) DO UPDATE SET
                total_tokens = token_usage_daily.total_tokens + $4,
                prompt_tokens = token_usage_daily.prompt_tokens + $5,
                completion_tokens = token_usage_daily.completion_tokens + $6,
                estimated_cost_usd = token_usage_daily.estimated_cost_usd + $7,
                request_count = token_usage_daily.request_count + 1
                """,
                user_id, today, organization_id, tokens, prompt_tokens, completion_tokens, cost_usd
            )
    
    async def get_audit_summary(
        self,
        start_time: datetime,
        end_time: datetime,
        organization_id: Optional[UUID] = None,
    ) -> AuditSummary:
        """Get audit summary for a time period."""
        if not self.pool:
            return AuditSummary(start_time=start_time, end_time=end_time)
        
        async with self.pool.acquire() as conn:
            org_filter = "AND organization_id = $3" if organization_id else ""
            params = [start_time, end_time]
            if organization_id:
                params.append(organization_id)
            
            row = await conn.fetchrow(
                f"""
                SELECT 
                    COUNT(*) as total_events,
                    COUNT(DISTINCT user_id) as unique_users,
                    SUM((metrics->>'total_tokens')::int) as total_tokens,
                    SUM((metrics->>'estimated_cost_usd')::float) as estimated_cost,
                    SUM(CASE WHEN (security_flags->>'pii_detected')::boolean = true 
                             OR (security_flags->>'prompt_injection_detected')::boolean = true 
                        THEN 1 ELSE 0 END) as security_incidents
                FROM audit_logs
                WHERE timestamp BETWEEN $1 AND $2 {org_filter}
                """,
                *params
            )
            
            # Get event type breakdown
            event_rows = await conn.fetch(
                f"""
                SELECT event_type, COUNT(*) as count
                FROM audit_logs
                WHERE timestamp BETWEEN $1 AND $2 {org_filter}
                GROUP BY event_type
                """,
                *params
            )
            
            # Get provider breakdown
            provider_rows = await conn.fetch(
                f"""
                SELECT provider, COUNT(*) as count
                FROM audit_logs
                WHERE timestamp BETWEEN $1 AND $2 {org_filter} AND provider IS NOT NULL
                GROUP BY provider
                """,
                *params
            )
            
            return AuditSummary(
                total_events=row['total_events'] or 0,
                events_by_type={r['event_type']: r['count'] for r in event_rows},
                events_by_provider={r['provider']: r['count'] for r in provider_rows},
                unique_users=row['unique_users'] or 0,
                total_tokens=row['total_tokens'] or 0,
                estimated_cost=float(row['estimated_cost'] or 0),
                security_incidents=row['security_incidents'] or 0,
                start_time=start_time,
                end_time=end_time,
            )


# Global database instance
db = Database()


async def get_database() -> Database:
    """Get database instance."""
    return db
