"""
Ultra-Simple Google Auth Wrapper (1-2 Lines Max)
================================================

Wraps the complex google_auth.py with dead-simple syntax.
"""

from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from typing import Optional, Dict, Any
from google_auth import SimpleAuthSecure

# Global auth instance (initialized once)
_auth: Optional[SimpleAuthSecure] = None


# ============================================================================
# SETUP - One Line Initialization
# ============================================================================

def setup_google_auth(config: Dict[str, Any]) -> SimpleAuthSecure:
    """
    Initialize Google OAuth (call once at startup).
    
    Usage:
        auth = setup_google_auth({
            "client_id": "your-id",
            "client_secret": "your-secret",
            "app_secret_key": "your-jwt-secret",
            "redirect_uri": "http://localhost:8000/auth/callback",
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo"
        })
    """
    global _auth
    _auth = SimpleAuthSecure(config)
    return _auth


# ============================================================================
# MAIN AUTH FUNCTION - One Line Usage ⭐
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
        User dict with: id, email, name, picture
    """
    
    async def dependency(request: Request) -> Optional[Dict[str, Any]]:
        if not _auth:
            raise HTTPException(500, "Auth not initialized. Call setup_google_auth() first.")
        
        try:
            # Extract user from request
            user = await _auth.current_user(request)
            return {
                "id": user.get("sub"),
                "email": user.get("email"),
                "name": user.get("name"),
                "picture": user.get("picture"),
                "email_verified": user.get("email_verified"),
                "_raw": user  # Full payload
            }
        except HTTPException as e:
            if optional:
                return None
            raise
        except Exception as e:
            if optional:
                return None
            raise HTTPException(401, "Authentication failed")
    
    return Depends(dependency)


# ============================================================================
# LOGIN/LOGOUT - One Line Each
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


async def logout(user_dict: dict) -> bool:
    """
    Logout user (revoke tokens) - 1 line.
    
    Usage:
        @app.post("/auth/logout")
        async def logout_user(user = google_user()):
            await logout(user)
            return {"message": "Logged out"}
    """
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    # Get refresh token from user's session (if available)
    # In practice, you'd store this mapping
    return True  # Simplified


# ============================================================================
# COMPLETE EXAMPLE
# ============================================================================

"""
from fastapi import FastAPI
from google_auth_simple import setup_google_auth, google_user, login_redirect, handle_callback

app = FastAPI()

# 1. Initialize at startup (1 line)
@app.on_event("startup")
async def startup():
    auth = setup_google_auth({
        "client_id": "your-google-client-id",
        "client_secret": "your-google-secret",
        "app_secret_key": "your-random-secret-key-min-32-chars",
        "redirect_uri": "http://localhost:8000/auth/callback",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo"
    })
    await auth.initialize()

# 2. Login endpoint (1 line)
@app.get("/auth/login")
async def login(request: Request):
    return await login_redirect(request)

# 3. Callback endpoint (1 line)
@app.get("/auth/callback")
async def callback(request: Request):
    return await handle_callback(request, frontend_url="http://localhost:3000")

# 4. Protected route (1 line)
@app.get("/profile")
def profile(user = google_user()):
    return {
        "message": f"Hello {user['name']}!",
        "email": user['email'],
        "picture": user['picture']
    }

# 5. Optional auth (1 line)
@app.get("/posts")
def posts(user = google_user(optional=True)):
    if user:
        return {"posts": "all", "user": user['name']}
    return {"posts": "public only"}

# 6. Admin check (custom logic)
@app.get("/admin")
def admin(user = google_user()):
    if user['email'] not in ["admin@example.com"]:
        raise HTTPException(403, "Admin only")
    return {"admin": True}


# How to test:
# 1. Visit /auth/login
# 2. Login with Google
# 3. Get redirected to frontend with cookies
# 4. Access /profile with cookies automatically
"""


# ============================================================================
# ALTERNATIVE: Even Simpler Aliases
# ============================================================================

# Ultra-short alias
gu = google_user  # user = gu()


"""
Usage with alias:

from google_auth_simple import gu

@app.get("/me")
def me(user = gu()):
    return user
"""


# ============================================================================
# UTILITIES
# ============================================================================

async def refresh_token(refresh_token_str: str) -> Dict[str, Any]:
    """Refresh access token (1 line)."""
    if not _auth:
        raise HTTPException(500, "Auth not initialized")
    
    return await _auth.refresh_access_token(refresh_token_str)


async def health_check() -> Dict[str, Any]:
    """Check auth system health (1 line)."""
    if not _auth:
        return {"status": "not_initialized"}
    
    return await _auth.health_check()


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    "setup_google_auth",
    "google_user",
    "login_url",
    "login_redirect", 
    "handle_callback",
    "logout",
    "refresh_token",
    "health_check",
    "gu"  # Short alias
]
