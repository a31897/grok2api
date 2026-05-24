"""Linux.do OIDC login and self-service user API."""

import base64
import json
import secrets
import urllib.parse
import urllib.request
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.platform.auth.middleware import verify_user_session
from app.platform.config.snapshot import get_config
from app.platform.users import AuthContext, SESSION_COOKIE, get_user_store

router = APIRouter(tags=["Users"])

_STATE_COOKIE = "grok2api_linuxdo_state"
_NONCE_COOKIE = "grok2api_linuxdo_nonce"
_NEXT_COOKIE = "grok2api_linuxdo_next"


class CreateSelfApiKeyRequest(BaseModel):
    name: str = "default"


def _enabled() -> bool:
    return bool(get_config("auth.linuxdo.enabled", False))


def _callback_url(request: Request) -> str:
    configured = str(get_config("auth.linuxdo.redirect_uri", "") or "").strip()
    if configured:
        return configured
    app_url = str(get_config("app.app_url", "") or "").rstrip("/")
    if app_url:
        return f"{app_url}/auth/linuxdo/callback"
    return str(request.url_for("linuxdo_callback"))


def _secure_cookie() -> bool:
    return str(get_config("app.app_url", "") or "").lower().startswith("https://")


def _http_json(url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None) -> dict[str, Any]:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode("utf-8", "replace")
    return json.loads(raw)


def _discovery() -> dict[str, Any]:
    url = str(
        get_config(
            "auth.linuxdo.discovery_url",
            "https://connect.linux.do/.well-known/openid-configuration",
        )
        or ""
    ).strip()
    if not url:
        issuer = str(get_config("auth.linuxdo.issuer", "https://connect.linux.do") or "").rstrip("/")
        url = f"{issuer}/.well-known/openid-configuration"
    return _http_json(url, headers={"Accept": "application/json"})


def _decode_id_token(id_token: str | None) -> dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8"))
    except Exception:
        return {}


def _exchange_code(discovery: dict[str, Any], code: str, redirect_uri: str) -> dict[str, Any]:
    client_id = str(get_config("auth.linuxdo.client_id", "") or "").strip()
    client_secret = str(get_config("auth.linuxdo.client_secret", "") or "").strip()
    if not client_id or not client_secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Linux.do OAuth client is not configured.")
    token_endpoint = discovery.get("token_endpoint")
    if not token_endpoint:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "OIDC discovery is missing token_endpoint.")
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        }
    ).encode()
    return _http_json(
        str(token_endpoint),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data=body,
    )


def _userinfo(discovery: dict[str, Any], access_token: str | None) -> dict[str, Any]:
    endpoint = discovery.get("userinfo_endpoint")
    if not endpoint or not access_token:
        return {}
    return _http_json(
        str(endpoint),
        headers={"Accept": "application/json", "Authorization": f"Bearer {access_token}"},
    )


def _safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/webui/chat"


@router.get("/auth/linuxdo/status", include_in_schema=False)
async def linuxdo_status(request: Request):
    return {
        "enabled": _enabled(),
        "login_url": "/auth/linuxdo/login",
        "callback_url": _callback_url(request),
    }


@router.get("/auth/linuxdo/login", include_in_schema=False)
async def linuxdo_login(request: Request, next: str | None = None):
    if not _enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linux.do login is disabled.")
    discovery = await _to_thread(_discovery)
    authorization_endpoint = discovery.get("authorization_endpoint")
    if not authorization_endpoint:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "OIDC discovery is missing authorization_endpoint.")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    params = {
        "client_id": str(get_config("auth.linuxdo.client_id", "") or "").strip(),
        "redirect_uri": _callback_url(request),
        "response_type": "code",
        "scope": str(get_config("auth.linuxdo.scopes", "openid profile email") or "openid profile email"),
        "state": state,
        "nonce": nonce,
    }
    if not params["client_id"]:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Linux.do OAuth client_id is not configured.")
    url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"
    response = RedirectResponse(url)
    response.set_cookie(_STATE_COOKIE, state, max_age=600, httponly=True, secure=_secure_cookie(), samesite="lax")
    response.set_cookie(_NONCE_COOKIE, nonce, max_age=600, httponly=True, secure=_secure_cookie(), samesite="lax")
    response.set_cookie(_NEXT_COOKIE, _safe_next(next), max_age=600, httponly=True, secure=_secure_cookie(), samesite="lax")
    return response


@router.get("/auth/linuxdo/callback", name="linuxdo_callback", include_in_schema=False)
async def linuxdo_callback(request: Request, code: str | None = None, state: str | None = None):
    if not _enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linux.do login is disabled.")
    if not code or not state or state != request.cookies.get(_STATE_COOKIE):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OAuth state.")

    discovery = await _to_thread(_discovery)
    tokens = await _to_thread(_exchange_code, discovery, code, _callback_url(request))
    profile = _decode_id_token(tokens.get("id_token"))
    profile.update(await _to_thread(_userinfo, discovery, tokens.get("access_token")))
    profile["provider"] = "linuxdo"
    nonce = request.cookies.get(_NONCE_COOKIE)
    if profile.get("nonce") and nonce and profile.get("nonce") != nonce:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OIDC nonce.")

    min_level = int(get_config("auth.linuxdo.minimum_level", 0) or 0)
    level = _profile_level(profile)
    if level < min_level:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Linux.do account level is too low.")

    user = await get_user_store().upsert_oidc_user(profile)
    token = await get_user_store().create_session(user["id"])
    redirect_to = _safe_next(request.cookies.get(_NEXT_COOKIE))
    response = RedirectResponse(redirect_to)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(get_config("users.session_ttl_seconds", 2592000) or 2592000),
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
    )
    for cookie in (_STATE_COOKIE, _NONCE_COOKIE, _NEXT_COOKIE):
        response.delete_cookie(cookie)
    return response


@router.post("/auth/logout", include_in_schema=False)
async def logout(request: Request):
    await get_user_store().delete_session(request.cookies.get(SESSION_COOKIE))
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.get("/user/api/me")
async def user_me(ctx: AuthContext = Depends(verify_user_session)):
    user = dict(ctx.user or {})
    user["api_keys"] = await get_user_store().list_api_keys(user["id"])
    return {"user": user}


@router.post("/user/api/api-keys")
async def user_create_api_key(req: CreateSelfApiKeyRequest, ctx: AuthContext = Depends(verify_user_session)):
    user = ctx.user or {}
    if user.get("status") != "active" or not user.get("api_enabled"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API access is disabled for this user.")
    return await get_user_store().create_api_key(user["id"], req.name)


@router.delete("/user/api/api-keys/{key_id}")
async def user_delete_api_key(key_id: str, ctx: AuthContext = Depends(verify_user_session)):
    ok = await get_user_store().delete_api_key(key_id, (ctx.user or {})["id"])
    return {"deleted": ok}


async def _to_thread(func, *args):
    import asyncio

    return await asyncio.to_thread(func, *args)


def _profile_level(profile: dict[str, Any]) -> int:
    for key in ("trust_level", "linuxdo_trust_level", "level", "min_level"):
        try:
            return int(profile.get(key))
        except (TypeError, ValueError):
            continue
    return 0


__all__ = ["router"]
