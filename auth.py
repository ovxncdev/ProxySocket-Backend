# auth.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx
import hashlib
import secrets

router = APIRouter()

# In-memory session store (replace with Redis/DB in production)
sessions: dict[str, dict] = {}


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    session_token: str
    api_key: str
    message: str


class LogoutRequest(BaseModel):
    session_token: str


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Authenticate with 9Proxy and return a session token.
    The iOS app uses this token for subsequent API calls.
    """
    try:
        nine_proxy_session = await authenticate_nine_proxy(
            request.email,
            request.password
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

    # Generate session token for our app
    session_token = secrets.token_hex(32)

    # Store session
    sessions[session_token] = {
        "email": request.email,
        "nine_proxy_cookies": nine_proxy_session["cookies"],
        "api_key": nine_proxy_session["api_key"],
    }

    return LoginResponse(
        session_token=session_token,
        api_key=nine_proxy_session["api_key"],
        message="Login successful"
    )


@router.post("/logout")
async def logout(request: LogoutRequest):
    """Remove session."""
    sessions.pop(request.session_token, None)
    return {"message": "Logged out"}


def get_session(session_token: str) -> dict:
    """Retrieve a stored session or raise 401."""
    session = sessions.get(session_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session


async def authenticate_nine_proxy(email: str, password: str) -> dict:
    """
    Login to 9Proxy and capture session cookies + API key.
    This is the reverse proxy layer — the iOS app never
    talks to 9Proxy directly.
    """
    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Step 1: Hit the login endpoint
        login_url = "https://9proxy.com/api/auth/login"

        payload = {
            "email": email,
            "password": password,
        }

        response = await client.post(
            login_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ProxySocket/1.0",
            }
        )

        if response.status_code != 200:
            raise Exception("Invalid credentials or 9Proxy login failed")

        data = res
