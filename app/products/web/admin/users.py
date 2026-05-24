"""Admin user management endpoints."""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.platform.users import get_user_store

router = APIRouter(tags=["Admin - Users"])


class UserPatchRequest(BaseModel):
    role: str | None = None
    status: str | None = None
    webchat_enabled: bool | None = None
    api_enabled: bool | None = None
    quota_limit: int | None = None
    quota_window_seconds: int | None = None
    quota_used: int | None = None
    quota_reset_at: int | None = None
    allowed_models: list[str] | None = None
    notes: str | None = None


class CreateUserApiKeyRequest(BaseModel):
    name: str = "admin"


@router.get("/users")
async def list_users():
    return {"users": await get_user_store().list_users()}


@router.patch("/users/{user_id:path}")
async def patch_user(user_id: str, req: UserPatchRequest):
    patch = req.model_dump(exclude_none=True)
    try:
        return {"user": await get_user_store().patch_user(user_id, patch)}
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found") from None


@router.post("/users/{user_id:path}/quota/reset")
async def reset_user_quota(user_id: str):
    try:
        return {"user": await get_user_store().reset_quota(user_id)}
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found") from None


@router.post("/users/{user_id:path}/api-keys")
async def create_user_api_key(user_id: str, req: CreateUserApiKeyRequest):
    user = await get_user_store().get_user(user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return await get_user_store().create_api_key(user_id, req.name)


@router.delete("/users/api-keys/{key_id}")
async def delete_user_api_key(key_id: str):
    return {"deleted": await get_user_store().delete_api_key(key_id)}


@router.delete("/users/{user_id:path}")
async def delete_user(user_id: str):
    deleted = await get_user_store().delete_user(user_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return {"deleted": True}


__all__ = ["router"]
