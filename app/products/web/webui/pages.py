"""Static page routes for the statics-based WebUI."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse

from app.platform.auth.middleware import is_user_auth_enabled, is_webui_enabled, verify_webui_key
from ..static_html import serve_static_html

router = APIRouter(include_in_schema=False)

STATIC_DIR = Path(__file__).resolve().parents[3] / "statics" / "webui"


def _serve(filename: str) -> FileResponse:
    path = STATIC_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Page not found")
    return FileResponse(path)


def _serve_html(filename: str):
    return serve_static_html(STATIC_DIR / filename)


async def _webui_page_guard(request: Request):
    if not is_webui_enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    if not is_user_auth_enabled():
        return None
    try:
        await verify_webui_key(request)
    except HTTPException as exc:
        if exc.status_code == 401:
            return RedirectResponse("/webui/login")
        raise
    return None


@router.get("/webui/chat")
async def webui_chat_page(request: Request):
    if redirect := await _webui_page_guard(request):
        return redirect
    return _serve_html("chat.html")


@router.get("/webui/chatkit")
async def webui_chatkit_page(request: Request):
    if redirect := await _webui_page_guard(request):
        return redirect
    return _serve_html("chatkit.html")


@router.get("/webui/masonry")
async def webui_masonry_page(request: Request):
    if redirect := await _webui_page_guard(request):
        return redirect
    return _serve_html("masonry.html")


__all__ = ["router"]
