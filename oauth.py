"""
Ultra-Simple Google Auth Wrapper with Redis Support
===================================================

Enhanced wrapper with:
- Redis storage backend support
- Proper logout/token revocation
- Session management
- Token refresh functionality
"""

from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from typing import Optional, Dict, Any
from google_auth import SimpleAuthSecure, StorageBackend
import asyncio
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Global auth instance (initialized once)
_auth: Optional[SimpleAuthSecure] = None
_token_mapping: Dict[str, str] = {}  # Maps user_id to refresh_token


# ============================================================================
# REDIS STORAGE BACKEND
# ============================================================================

class RedisStorage(StorageBackend):
    """
    Redis storage backend for production use.
    
    Requires: pip install redis[asyncio]
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """
        Initialize Redis storage.
        
        Args:
            redis_url: Redis connection URL
        """
        try:
            import redis.asyncio as aioredis
            self._redis_module = aioredis
        except ImportError:
            raise ImportError(
                "Redis support requires 'redis' package. "
                "Install with: pip install redis[asyncio]"
            )
        
        self.redis_url = redis_url
        self._client: Optional[aioredis.Redis] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        logger.info(f"Redis storage initialized with URL: {redis_url}")
    
    async def _get_client(self):
        """Get or create Redis client."""
        if not self._client:
            self._client = self._redis_module.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            # Test connection
            await self._client.ping()
            logger.info("Redis connection established")
        return self._client
    
    async def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        """Store a value with TTL in Redis."""
        import json
        client = await self._get_client()
        json_value = json.dumps(value)
        await client.setex(key, ttl_seconds, json_value)
    
    async def get(self, key: str) -> Optional[dict]:
        """Retrieve a value from Redis."""
        import json
        client = await self._get_client()
        value = await client.get(key)
        if value:
            return json.loads(value)
        return None
    
    async def delete(self, key: str) -> None:
        """Delete a key from Redis."""
        client = await self._get_client()
        await client.delete(key)
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists in Redis."""
        client = await self._get_client()
        result = await client.exists(key)
        return bool(result)
    
    async def start_cleanup(self) -> None:
        """
        Start cleanup task for Redis.
        
        Note: Redis handles TTL expiration automatically, so this is a no-op.
        """
        logger.info("Redis cleanup: Redis handles TTL automatically, no cleanup task needed")
    
    async def stop_cleanup(self) -> None:
        """Stop cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Redis cleanup task stopped")
    
    async def stop(self) -> None:
        """Stop storage backend and cleanup."""
        await self.stop_cleanup()
        logger.info("Redis storage stopped")
    
    async def close(self):
        """Close Redis connection."""
        await self.stop_cleanup()
        
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")


# ============================================================================
# SETUP - Enhanced with Redis Support
# ============================================================================

def setup_google_auth(
    config: Dict[str, Any],
    use_redis: bool = False,
    redis_url: str = "redis://localhost:6379/0"
) -> SimpleAuthSecure:
    """
    Initialize Google OAuth with optional Redis support.
    
    Usage:
        # Without Redis (in-memory, development only)
        auth = setup_google_auth({
            "client_id": "your-id",
            "client_secret": "your-secret",
            "app_secret_key": "your-jwt-secret",
            "redirect_uri": "http://localhost:8000/auth/callback",
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo"
        })
        
        # With Redis (production)
        auth = setup_google_auth(
            config={...},
            use_redis=True,
            redis_url="redis://localhost:6379/0"
        )
    
    Args:
        config: OAuth configuration dictionary
        use_redis: Enable Redis storage backend (default: False)
        redis_url: Redis connection URL (default: redis://localhost:6379/0)
    
    Returns:
        Initialized SimpleAuthSecure instance
    """
    global _auth
    
    storage = None
    if use_redis:
        logger.info("Initializing with Redis storage backend")
        storage = RedisStorage(redis_url)
    else:
        logger.warning("Using in-memory storage - not recommended for production")
    
    _auth = SimpleAuthSecure(config, storage=storage)
    return _auth


# ============================================================================
# MAIN AUTH FUNCTION - Enhanced with Token Tracking
# ============================================================================

def google_user(optional: bool = False):
    """
    Get authenticated Google user (1 line).
    
    Usage:
        @app.get("/profile")
        def profile(user = google_user()):
            return user
        
        @app.get("/public")
        def public(user = google_user(optional=True)):
            return user or "guest"
    
    Returns:
        User dict with: id, email, name, picture, refresh_token
    """
    
    async def dependency(request: Request) -> Optional[Dict[str, Any]]:
        if not _auth:
            raise HTTPException(500, "Auth not initialized. Call setup_google_auth() first.")
        
        try:
            # Get access token
            access_token = request.cookies.get("access_token")
            
            # Check if token is blacklisted
            if access_token and _auth._store:
                try:
                    blacklisted = await _auth._store.get(f"blacklist:{access_token}")
                    if blacklisted:
                        logger.warning("Blacklisted token attempted to be used")
                        raise HTTPException(401, "Token has been revoked")
                except Exception as e:
                    if "blacklist" in str(e).lower():
                        pass  # Key doesn't exist, token is not blacklisted
                    else:
                        logger.error(f"Blacklist check error: {e}")
            
            # Extract user from request
            user_payload = await _auth.current_user(request)
            
            # Get refresh token from cookie for logout support
            refresh_token = request.cookies.get("refresh_token")
            
            user_data = {
                "id": user_payload.get("sub"),
                "email": user_payload.get("email"),
                "name": user_payload.get("name"),
                "picture": user_payload.get("picture"),
                "email_verified": user_payload.get("email_verified"),
                "refresh_token": refresh_token,  # Include for logout
                "_raw": user_payload  # Full payload
            }
            
            # Track user_id to refresh_token mapping for logout
            if refresh_token:
                _token_mapping[user_payload.get("sub")] = refresh_token
            
            return user_data
            
        except HTTPException as e:
            if optional:
                return None
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            if optional:
                return None
            raise HTTPException(401, "Authentication failed")
    
    return Depends(dependency)


# ============================================================================
# LOGIN/LOGOUT - Enhanced with Proper Token Revocation
# ============================================================================

async def login_url(request: Request) -> str:
    """
    Get Google login URL (1 line).
    
    Usage:
        @app.get("/auth/login")
        async def login(request: Request):
            url = await login_url(request)
            return {"login_url": url}
    """
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    result = await _auth.get_login_url(request)
    return result["login_url"]


async def login_redirect(request: Request) -> RedirectResponse:
    """
    Redirect to Google login (1 line).
    
    Usage:
        @app.get("/auth/login")
        async def login(request: Request):
            return await login_redirect(request)
    """
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    return await _auth.login_redirect(request)


async def handle_callback(request: Request, frontend_url: str = "http://localhost:3000") -> RedirectResponse:
    """
    Handle Google callback (1 line).
    
    Usage:
        @app.get("/auth/callback")
        async def callback(request: Request):
            return await handle_callback(request, "http://localhost:3000")
    """
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    return await _auth.handle_callback_redirect(request, frontend_url)


async def logout(
    user_dict: Optional[dict] = None,
    request: Optional[Request] = None,
    response: Optional[Any] = None
) -> dict:
    """
    Logout user (revoke tokens and clear cookies).
    
    Usage:
        # Method 1: With user dict from google_user()
        @app.post("/auth/logout")
        async def logout_user(user = google_user()):
            result = await logout(user_dict=user)
            return result
        
        # Method 2: With request (extracts token from cookies)
        @app.post("/auth/logout")
        async def logout_user(request: Request):
            result = await logout(request=request)
            return result
        
        # Method 3: With response (clears cookies)
        @app.post("/auth/logout")
        async def logout_user(request: Request, response: Response):
            result = await logout(request=request, response=response)
            return result
    
    Returns:
        Dictionary with logout status
    """
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    refresh_token = None
    access_token = None
    user_id = None
    
    # Extract tokens from various sources
    if user_dict:
        refresh_token = user_dict.get("refresh_token")
        user_id = user_dict.get("id")
    
    if request:
        if not refresh_token:
            refresh_token = request.cookies.get("refresh_token")
        access_token = request.cookies.get("access_token")
        
        # Try to get user_id from access token
        if not user_id:
            try:
                user_payload = await _auth.current_user(request)
                user_id = user_payload.get("sub")
            except:
                pass
    
    if not refresh_token:
        # Check token mapping
        if user_id and user_id in _token_mapping:
            refresh_token = _token_mapping[user_id]
    
    if not refresh_token and not access_token:
        logger.warning("No tokens found for logout")
        return {
            "success": False,
            "message": "No active session found"
        }
    
    # 1. Blacklist access token in Redis
    if access_token:
        try:
            await _auth._store.set(
                f"blacklist:{access_token}",
                {"revoked": True, "user_id": user_id},
                ttl_seconds=3600  # 1 hour (match token expiry)
            )
            logger.info(f"Access token blacklisted for user: {user_id}")
        except Exception as e:
            logger.error(f"Failed to blacklist access token: {e}")
    
    # 2. Revoke the refresh token
    try:
        if refresh_token:
            revoked = await _auth.revoke_refresh_token(refresh_token)
        else:
            revoked = True  # No refresh token to revoke
        
        # Clear token mapping
        if user_id and user_id in _token_mapping:
            del _token_mapping[user_id]
        
        # Clear cookies if response provided
        if response:
            response.delete_cookie("access_token", path="/")
            response.delete_cookie("refresh_token", path="/")
        
        logger.info(f"User logged out successfully: {user_id}")
        return {
            "success": True,
            "message": "Logged out successfully"
        }
            
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(500, f"Logout failed: {str(e)}")


# ============================================================================
# TOKEN MANAGEMENT
# ============================================================================

async def refresh_token(
    refresh_token_str: Optional[str] = None,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Refresh access token.
    
    Usage:
        # Method 1: Direct refresh token
        @app.post("/auth/refresh")
        async def refresh(refresh_token: str):
            return await refresh_token(refresh_token_str=refresh_token)
        
        # Method 2: From request cookies
        @app.post("/auth/refresh")
        async def refresh(request: Request):
            return await refresh_token(request=request)
    
    Returns:
        New tokens dictionary
    """
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    # Extract refresh token
    if not refresh_token_str and request:
        refresh_token_str = request.cookies.get("refresh_token")
    
    if not refresh_token_str:
        raise HTTPException(400, "No refresh token provided")
    
    # Get client identifier for rate limiting
    client_id = None
    if request:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_id = forwarded.split(",")[0].strip()
        else:
            client_id = request.client.host if request.client else None
    
    try:
        return await _auth.refresh_access_token(refresh_token_str, client_id)
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(401, "Token refresh failed")


# ============================================================================
# UTILITIES
# ============================================================================

async def health_check() -> Dict[str, Any]:
    """
    Check auth system health.
    
    Usage:
        @app.get("/auth/health")
        async def health():
            return await health_check()
    """
    if not _auth:
        return {
            "status": "not_initialized",
            "storage": "unknown",
            "redis": False
        }
    
    health = await _auth.health_check()
    
    # Add Redis status
    if hasattr(_auth._store, '_redis_module'):
        health["redis"] = "enabled"
    else:
        health["redis"] = "disabled"
    
    return health


async def get_metrics() -> Dict[str, Any]:
    """
    Get authentication metrics.
    
    Usage:
        @app.get("/auth/metrics")
        async def metrics():
            return await get_metrics()
    """
    if not _auth:
        return {"error": "Auth not initialized"}
    
    return _auth.get_metrics()


async def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token.
    
    Usage:
        @app.post("/auth/verify")
        async def verify(token: str):
            return await verify_token(token)
    """
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    try:
        return await _auth.verify_access_token(token)
    except Exception as e:
        raise HTTPException(401, f"Token verification failed: {str(e)}")


# ============================================================================
# CLEANUP
# ============================================================================

async def shutdown():
    """
    Shutdown auth system and cleanup resources.
    
    Usage:
        @app.on_event("shutdown")
        async def app_shutdown():
            await shutdown()
    """
    global _auth, _token_mapping
    
    if _auth:
        await _auth.shutdown()
        
        # Close Redis connection if using Redis
        if hasattr(_auth._store, 'close'):
            await _auth._store.close()
        
        _auth = None
    
    _token_mapping.clear()
    logger.info("Auth system shutdown complete")


# ============================================================================
# ALIASES
# ============================================================================

gu = google_user  # Ultra-short alias


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    # Setup
    "setup_google_auth",
    "RedisStorage",
    
    # Main functions
    "google_user",
    "login_url",
    "login_redirect", 
    "handle_callback",
    "logout",
    
    # Token management
    "refresh_token",
    "verify_token",
    
    # Utilities
    "health_check",
    "get_metrics",
    "shutdown",
    
    # Aliases
    "gu"
]
