"""XAI console Responses protocol for direct Grok model calls."""

from typing import Any, AsyncGenerator

import orjson

from app.platform.config.snapshot import get_config
from app.platform.errors import UpstreamError
from app.platform.logging.logger import logger
from app.control.model.enums import ModeId
from app.dataplane.proxy.adapters.headers import build_http_headers
from app.dataplane.proxy.adapters.session import ResettableSession, build_session_kwargs
from app.dataplane.reverse.runtime.endpoint_table import (
    CONSOLE_BASE,
    CONSOLE_RESPONSES,
)


def is_console_responses_mode(mode_id: ModeId, mode_name: str | None = None) -> bool:
    """Return whether a request should use the console Responses endpoint."""
    if mode_id == ModeId.GROK_4_3:
        return True
    normalised = (mode_name or "").strip().lower()
    return normalised in {"grok-4.3", "grok-4.3-beta", "grok4.3"}


def build_responses_payload(
    *,
    message: str,
    model: str,
    file_inputs: list[str] = (),
    request_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the JSON payload for ``POST /v1/responses`` on console.x.ai."""
    cfg = get_config()
    input_value: str | list[dict[str, Any]]

    if file_inputs:
        content: list[dict[str, Any]] = [{"type": "input_text", "text": message}]
        for item in file_inputs:
            if not item:
                continue
            content.append({"type": "input_image", "image_url": item})
        input_value = [{"role": "user", "content": content}]
    else:
        input_value = message

    payload: dict[str, Any] = {
        "model": model,
        "input": input_value,
        "stream": True,
        "store": not cfg.get_bool("features.temporary", True),
    }

    custom = cfg.get_str("features.custom_instruction", "").strip()
    if custom:
        payload["instructions"] = custom

    if request_overrides:
        for key, value in request_overrides.items():
            if value is not None:
                payload[key] = value
        payload["model"] = model
        payload["stream"] = True

    logger.debug(
        "console responses payload built: model={} message_len={} file_count={}",
        model,
        len(message),
        len(file_inputs),
    )
    return payload


def _app_chat_sse(response: dict[str, Any]) -> str:
    return f"data: {orjson.dumps({'result': {'response': response}}).decode()}\n\n"


def _extract_error_message(obj: dict[str, Any]) -> str:
    error = obj.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("error") or error)
    if error:
        return str(error)
    response = obj.get("response")
    if isinstance(response, dict):
        nested = response.get("error")
        if isinstance(nested, dict):
            return str(nested.get("message") or nested.get("error") or nested)
        if nested:
            return str(nested)
    return "Console Responses upstream error"


def _raise_for_responses_error(obj: dict[str, Any]) -> None:
    event_type = obj.get("type")
    response = obj.get("response") if isinstance(obj.get("response"), dict) else {}
    has_error = (
        event_type in {"response.failed", "response.incomplete"}
        or obj.get("error")
        or response.get("error")
    )
    if has_error:
        try:
            body = orjson.dumps(obj).decode()
        except (TypeError, ValueError):
            body = str(obj)
        message = _extract_error_message(obj)
        text = message.lower()
        status = 429 if "rate limit" in text or "too many requests" in text else 502
        raise UpstreamError(message, status=status, body=body[:400])


def responses_event_to_app_chat_lines(obj: dict[str, Any]) -> list[str]:
    """Convert Responses API SSE event payloads into app-chat-like frames."""
    _raise_for_responses_error(obj)

    event_type = obj.get("type", "")
    if event_type == "response.output_text.delta":
        delta = obj.get("delta")
        if delta:
            return [_app_chat_sse({
                "token": str(delta),
                "isThinking": False,
                "messageTag": "final",
            })]
        return []

    if event_type == "response.reasoning_summary_text.delta":
        delta = obj.get("delta")
        if delta:
            return [_app_chat_sse({
                "token": str(delta),
                "isThinking": True,
                "messageTag": "thinking",
            })]
        return []

    if event_type == "response.output_text.annotation.added":
        annotation = obj.get("annotation")
        if isinstance(annotation, dict) and annotation.get("url"):
            try:
                index = int(obj.get("annotation_index", 0)) + 1
            except (TypeError, ValueError):
                index = 1
            return [_app_chat_sse({
                "token": f" [[{index}]]({annotation['url']})",
                "isThinking": False,
                "messageTag": "final",
            })]
        return []

    if event_type == "response.completed":
        return [_app_chat_sse({"isSoftStop": True}), "data: [DONE]\n\n"]

    return []


async def stream_console_responses(
    *,
    token: str,
    model: str,
    message: str,
    files: list[str],
    request_overrides: dict[str, Any] | None = None,
    timeout_s: float = 120.0,
    lease=None,
) -> AsyncGenerator[str, None]:
    """Yield app-chat-compatible SSE lines from ``console.x.ai/v1/responses``."""
    payload = build_responses_payload(
        message=message,
        model=model,
        file_inputs=files,
        request_overrides=request_overrides,
    )
    payload_bytes = orjson.dumps(payload)

    headers = build_http_headers(
        token,
        content_type="application/json",
        origin=CONSOLE_BASE,
        referer=f"{CONSOLE_BASE}/",
        lease=lease,
    )
    headers["Accept"] = "text/event-stream, application/json, */*"

    session_kwargs = build_session_kwargs(lease=lease)
    async with ResettableSession(**session_kwargs) as session:
        try:
            response = await session.post(
                CONSOLE_RESPONSES,
                headers=headers,
                data=payload_bytes,
                timeout=timeout_s,
                stream=True,
            )
        except Exception as exc:
            raise UpstreamError(
                f"Console responses transport failed: {exc}",
                status=502,
                body=str(exc).replace("\n", "\\n")[:400],
            ) from exc

        if response.status_code != 200:
            try:
                body = response.content.decode("utf-8", "replace")[:400]
            except Exception:
                body = ""
            raise UpstreamError(
                f"Console responses upstream returned {response.status_code}",
                status=response.status_code,
                body=body,
            )

        try:
            async for line in response.aiter_lines():
                if not line:
                    continue
                if isinstance(line, bytes):
                    line = line.decode("utf-8", "replace")
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    yield "data: [DONE]\n\n"
                    continue
                try:
                    obj = orjson.loads(data)
                except (orjson.JSONDecodeError, ValueError, TypeError):
                    continue
                if not isinstance(obj, dict):
                    continue
                for out in responses_event_to_app_chat_lines(obj):
                    yield out
        except UpstreamError:
            raise
        except Exception as exc:
            raise UpstreamError(
                f"Console responses stream read failed: {exc}",
                status=502,
                body=str(exc).replace("\n", "\\n")[:400],
            ) from exc


__all__ = [
    "is_console_responses_mode",
    "build_responses_payload",
    "responses_event_to_app_chat_lines",
    "stream_console_responses",
]
