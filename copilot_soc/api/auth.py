"""PBKDF2-HMAC-SHA256 authentication with HMAC-signed session tokens.

Hash: salt (hex) + "$" + digest (hex) — stored in users.password_hash.
Session token: ``{user_id}|{tenant_id}|{role}|{HMAC-SHA256}`` — stored in an
httponly cookie named ``soc_session`` with 7-day expiry.

Roles: analyst (read alerts), governor (approve/reject), admin (settings).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import ValidationError

from copilot_soc.api.deps import get_db
from copilot_soc.models import LoginRequest

router = APIRouter(tags=["auth"])

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-this-session-secret")


def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with 120K iterations and a random 16-byte salt."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${digest.hex()}"


def _verify_password(password: str, password_hash: str) -> bool:
    """Constant-time compare to prevent timing attacks on login."""
    try:
        salt, expected = password_hash.split("$", 1)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return hmac.compare_digest(digest.hex(), expected)


def _issue_session_token(user_id: str, tenant_id: str, role: str) -> str:
    """HMAC-SHA256 signed session token: payload|signature."""
    payload = f"{user_id}|{tenant_id}|{role}"
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}|{signature}"


def verify_session_token(token: str) -> dict | None:
    """Validate HMAC signature and role, return user dict or None."""
    try:
        parts = token.split("|", 3)
        if len(parts) != 4:
            return None
        user_id, tenant_id, role, signature = parts
        payload = f"{user_id}|{tenant_id}|{role}"
        expected = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        if role not in {"analyst", "governor", "admin"}:
            return None
        return {"user_id": user_id, "tenant_id": tenant_id, "role": role}
    except (ValueError, IndexError):
        return None


def require_auth(request: Request) -> dict:
    """Extract the authenticated user from the soc_session cookie. Raises 401 on failure."""
    token = request.cookies.get("soc_session")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")
    user = verify_session_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session.")
    return user


def require_governor(request: Request) -> dict:
    """Like require_auth but also enforces governor or admin role (403 otherwise)."""
    user = require_auth(request)
    if user["role"] not in {"governor", "admin"}:
        raise HTTPException(status_code=403, detail="Governor or admin role required.")
    return user


@router.post("/api/login")
async def login(request: Request):
    """Authenticate via JSON or form POST; set the soc_session cookie on success."""
    db = await get_db()
    try:
        body = await request.json()
        payload = LoginRequest(
            email=str(body.get("email", "")).strip(),
            password=str(body.get("password", "")),
        )
    except (ValueError, ValidationError):
        try:
            form = await request.form()
            payload = LoginRequest(
                email=str(form.get("email", "")).strip(),
                password=str(form.get("password", "")),
            )
        except (ValueError, ValidationError):
            raise HTTPException(status_code=400, detail="Invalid email or password format.")

    tenant = await db.get_tenant_by_slug("default")
    if not tenant:
        raise HTTPException(status_code=500, detail="No tenant configured.")

    tenant_id = tenant["id"]
    email = payload.email
    if email == "admin":
        email = "admin@copilot-soc.local"
    user_record = await db.get_user_by_email(tenant_id, email)
    if not user_record or not _verify_password(payload.password, user_record["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = _issue_session_token(str(user_record["id"]), str(tenant_id), user_record["role"])
    response = Response(status_code=200)
    response.set_cookie(
        "soc_session", token,
        httponly=True, samesite="lax", max_age=86400 * 7,
    )
    return response


@router.post("/api/logout")
async def logout():
    """Clear the soc_session cookie."""
    response = Response(status_code=200)
    response.delete_cookie("soc_session")
    return response


@router.get("/api/me")
async def get_me(request: Request):
    """Return current user identity from the session cookie."""
    user = require_auth(request)
    return {"user_id": user["user_id"], "tenant_id": user["tenant_id"], "role": user["role"]}


async def _resolve_tenant(db) -> Optional[UUID]:
    """Return the first tenant_id from the DB (used by background collector)."""
    import asyncpg
    try:
        row = await db.pool.fetchrow("SELECT id FROM tenants LIMIT 1")
        return row["id"] if row else None
    except Exception:
        return None
