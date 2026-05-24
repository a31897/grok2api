"""Shared model availability helpers for API model listings."""

from fastapi import Request

from app.control.account.enums import AccountStatus
from app.control.account.quota_defaults import supports_mode
from app.control.account.state_machine import derive_status
from app.control.model.spec import ModelSpec

_POOL_ID_TO_NAME = {0: "basic", 1: "super", 2: "heavy"}


async def active_pools_for_request(request: Request) -> frozenset[str]:
    """Return account pools with at least one currently selectable account."""
    repo = getattr(request.app.state, "repository", None)
    if repo is None:
        return frozenset()

    snapshot = await repo.runtime_snapshot()
    pools = {
        record.pool
        for record in snapshot.items
        if not record.is_deleted() and derive_status(record) == AccountStatus.ACTIVE
    }
    return frozenset(pools)


def model_available_for_pools(spec: ModelSpec, pools: frozenset[str]) -> bool:
    """Return whether any active pool can serve *spec*."""
    if not spec.enabled:
        return False
    for pool_id in spec.pool_candidates():
        pool = _POOL_ID_TO_NAME.get(pool_id)
        if pool in pools and supports_mode(pool, int(spec.mode_id)):
            return True
    return False


__all__ = ["active_pools_for_request", "model_available_for_pools"]
