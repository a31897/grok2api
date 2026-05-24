"""API-key authentication dependencies for FastAPI routes."""

import hmac

from fastapi import Header, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.platform.config.snapshot import get_config
from app.platform.users import AuthContext, SESSION_COOKIE, get_user_store

_security = HTTPBearer(auto_error=False, scheme_name="API Key")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_keys() -> list[str]:
    raw = get_config("app.api_key", "")
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(k).strip() for k in raw if str(k).strip()]
    return [k.strip() for k in str(raw).split(",") if k.strip()]


def get_admin_key() -> str:
    """Return configured ``app.app_key`` (admin password)."""
    return str(get_config("app.app_key", "grok2api") or "")


def get_webui_key() -> str:
    """Return configured ``app.webui_key`` (webui access key)."""
    return str(get_config("app.webui_key", "") or "")


def is_webui_enabled() -> bool:
    """Whether the webui entry is enabled."""
    return _legacy_webui_enabled() or bool(get_config("auth.linuxdo.enabled", False))


def _legacy_webui_enabled() -> bool:
    val = get_config("app.webui_enabled", False)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in {"1", "true", "yes", "on"}
    return bool(val)


def is_user_auth_enabled() -> bool:
    return bool(get_config("users.enabled", False) or get_config("auth.linuxdo.enabled", False))


def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

async def verify_api_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="x-api-key"),
) -> None:
    """Validate Bearer token against configured ``api_key``.

    Accepts either ``Authorization: Bearer <key>`` (OpenAI / grok2api style)
    or ``X-API-Key: <key>`` (official Anthropic SDK style) so that agents
    targeting the Anthropic-compatible endpoint work without reconfiguration.
    """
    allowed_keys = _get_keys()
    users_enabled = is_user_auth_enabled()
    if not allowed_keys and not users_enabled:
        return

    token = _extract_bearer(authorization) or x_api_key or None
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid Authorization header.")

    if any(hmac.compare_digest(token, k) for k in allowed_keys):
        request.state.auth_context = AuthContext(kind="global_api_key", global_key=True)
        return

    if users_enabled:
        ctx = await get_user_store().lookup_api_key(token)
        if ctx is not None and ctx.user is not None:
            _ensure_user_can_call_api(ctx.user)
            request.state.auth_context = ctx
            if _should_consume_api_quota(request):
                await _consume_user_quota(ctx.user["id"])
            return

    raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid API key.")


async def verify_admin_key(
    authorization: str | None = Header(default=None),
    app_key: str | None = Query(default=None),
) -> None:
    """Validate Bearer token against ``app.app_key`` (admin access).

    Accepts either ``Authorization: Bearer <key>`` header or ``?app_key=<key>``
    query parameter (the latter is needed for EventSource which cannot send headers).
    """
    key = get_admin_key()
    if not key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Admin key is not configured.")

    token = _extract_bearer(authorization) or app_key
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing authentication token.")

    if not hmac.compare_digest(token, key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token.")


async def verify_webui_key(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    """Validate Bearer token for webui endpoints."""
    webui_key = get_webui_key()
    session_token = request.cookies.get(SESSION_COOKIE)
    ctx = await get_user_store().get_session(session_token) if is_user_auth_enabled() else None
    if ctx is not None and ctx.user is not None:
        _ensure_user_can_use_webchat(ctx.user)
        request.state.auth_context = ctx
        if request.method.upper() == "POST" and request.url.path.endswith("/chat/completions"):
            await _consume_user_quota(ctx.user["id"])
        return

    if not webui_key:
        if _legacy_webui_enabled():
            request.state.auth_context = AuthContext(kind="webui_global", global_key=True)
            return
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "WebUI access is disabled.")

    token = _extract_bearer(authorization)
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing authentication token.")

    if not hmac.compare_digest(token, webui_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token.")
    request.state.auth_context = AuthContext(kind="webui_key", global_key=True)


async def verify_user_session(request: Request) -> AuthContext:
    ctx = await get_user_store().get_session(request.cookies.get(SESSION_COOKIE))
    if ctx is None or ctx.user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing user session.")
    _ensure_user_active(ctx.user)
    request.state.auth_context = ctx
    return ctx


def _ensure_user_active(user: dict) -> None:
    if user.get("status") != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User is disabled.")


def _ensure_user_can_call_api(user: dict) -> None:
    _ensure_user_active(user)
    if not user.get("api_enabled"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API access is disabled for this user.")


def _ensure_user_can_use_webchat(user: dict) -> None:
    _ensure_user_active(user)
    if not user.get("webchat_enabled"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "WebChat access is disabled for this user.")


def _should_consume_api_quota(request: Request) -> bool:
    if request.method.upper() != "POST":
        return False
    path = request.url.path
    return path.startswith("/v1/") and "/files/" not in path


async def _consume_user_quota(user_id: str) -> None:
    user = await get_user_store().consume_quota(user_id, 1)
    if user.get("quota_exceeded"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"User quota exceeded. Resets at {user.get('quota_reset_at')}.",
        )


def allowed_models_for_request(request: Request) -> set[str] | None:
    ctx = getattr(request.state, "auth_context", None)
    if not isinstance(ctx, AuthContext) or not ctx.user:
        return None
    models = ctx.user.get("allowed_models") or []
    if not models:
        return None
    return {str(item) for item in models if str(item).strip()}


def enforce_model_access(request: Request, model: str) -> None:
    allowed = allowed_models_for_request(request)
    if allowed is not None and model not in allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Model {model!r} is not allowed for this user.")

__all__ = [
    "verify_api_key",
    "verify_admin_key",
    "verify_webui_key",
    "verify_user_session",
    "get_admin_key",
    "get_webui_key",
    "is_webui_enabled",
    "is_user_auth_enabled",
    "allowed_models_for_request",
    "enforce_model_access",
]
