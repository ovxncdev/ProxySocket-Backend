# auth.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx
import secrets

router = APIRouter()

# In-memory session store (replace with Redis/DB in production)
sessions: dict[str, dict] = {}

NINE_PROXY_BASE = "https://9proxy.com"


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    session_token: str
    message: str


class LogoutRequest(BaseModel):
    session_token: str


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Authenticate with 9Proxy web dashboard.
    Captures session cookies for subsequent API calls.
    """
    try:
        nine_proxy_session = await authenticate_nine_proxy(
            request.email,
            request.password
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

    session_token = secrets.token_hex(32)

    sessions[session_token] = {
        "email": request.email,
        "cookies": nine_proxy_session["cookies"],
        "headers": nine_proxy_session["headers"],
    }

    return LoginResponse(
        session_token=session_token,
        message="Login successful"
    )


@router.post("/logout")
async def logout(request: LogoutRequest):
    sessions.pop(request.session_token, None)
    return {"message": "Logged out"}


def get_session(session_token: str) -> dict:
    session = sessions.get(session_token)
    if not session:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session"
        )
    return session


async def authenticate_nine_proxy(email: str, password: str) -> dict:
    """
    Login to 9Proxy web dashboard.
    We use their sign-in page to authenticate and capture
    the session cookies needed for dashboard API calls.
    """
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=30.0
    ) as client:
        # Step 1: Get the login page to capture any CSRF tokens
        login_page = await client.get(f"{NINE_PROXY_BASE}/sign-in")
        initial_cookies = dict(login_page.cookies)

        # Step 2: Submit login form
        login_response = await client.post(
            f"{NINE_PROXY_BASE}/sign-in",
            data={
                "email": email,
                "password": password,
            },
            cookies=initial_cookies,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Referer": f"{NINE_PROXY_BASE}/sign-in",
                "Origin": NINE_PROXY_BASE,
            }
        )

        # Merge all cookies from the login flow
        all_cookies = {**initial_cookies, **dict(login_response.cookies)}

        # Check if login succeeded by looking for dashboard redirect
        # or session cookie presence
        if login_response.status_code >= 400:
            raise Exception("Invalid email or password")

        # Some sites use JSON login endpoints instead
        # Try JSON approach if form post didn't set session cookies
        if not all_cookies or len(all_cookies) < 2:
            login_response = await client.post(
                f"{NINE_PROXY_BASE}/api/auth/login",
                json={
                    "email": email,
                    "password": password,
                },
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                }
            )

            if login_response.status_code != 200:
                raise Exception("Invalid email or password")

            all_cookies = dict(login_response.cookies)

        # Build headers for future authenticated requests
        auth_headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Referer": f"{NINE_PROXY_BASE}/dashboard",
        }

        return {
            "cookies": all_cookies,
            "headers": auth_headers,
        }
