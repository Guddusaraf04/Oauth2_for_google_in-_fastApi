# Oauth2_for_google_in-_fastApi
This is small helper library help us to implement only Google auth only with proper security any with simple syntax.

It need some changes for async await proper support making this public 

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
