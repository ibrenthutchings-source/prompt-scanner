"""Provider-compatible reverse proxy.

Point any client's base URL at this gateway and it keeps working:

    Anthropic SDK   base_url = http://gateway:8000/anthropic
    OpenAI SDK      base_url = http://gateway:8000/openai/v1

Everything is passed through byte-for-byte except the scanned prompt fields, so
tool use, streaming, prompt caching, and beta headers all survive. Blocking
returns the provider's own error envelope with HTTP 403, which is what makes the
error render natively in Cursor, Continue, the SDKs, and curl — no client-side
integration required.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app import pipeline, redact
from app.config import get_settings
from app.db import get_session
from app.detect import fastgate
from app.models import Action
from app.proxy import extract
from app.schemas import AttachmentInfo, PromptContext, Verdict

log = logging.getLogger(__name__)
router = APIRouter(tags=["proxy"])

# Hop-by-hop headers must not be forwarded, and Host/Content-Length are
# recomputed by httpx from the (possibly redacted) body.
_STRIP_REQUEST = {
    "host", "content-length", "connection", "keep-alive", "transfer-encoding",
    "upgrade", "proxy-authorization", "proxy-authenticate", "te", "trailer",
    "accept-encoding",
}
_STRIP_RESPONSE = {
    "content-length", "content-encoding", "connection", "keep-alive",
    "transfer-encoding", "upgrade",
}

_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        s = get_settings()
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(s.upstream_timeout_s, connect=s.upstream_connect_timeout_s),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
    return _client


async def close_http_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


# ---------------------------------------------------------------------------
# Provider-shaped error envelopes
# ---------------------------------------------------------------------------


def _anthropic_error(verdict: Verdict) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "type": "error",
            "error": {"type": "permission_error", "message": verdict.message},
            "prompt_scanner": _scanner_block(verdict),
        },
        headers=_verdict_headers(verdict),
    )


def _openai_error(verdict: Verdict) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "message": verdict.message,
                "type": "invalid_request_error",
                "param": "messages",
                "code": "content_policy_violation",
            },
            "prompt_scanner": _scanner_block(verdict),
        },
        headers=_verdict_headers(verdict),
    )


def _scanner_block(verdict: Verdict) -> dict[str, Any]:
    return {
        "event_id": verdict.event_id,
        "action": verdict.action.value,
        "severity": verdict.severity.value,
        "risk_score": verdict.risk_score,
        "policy": verdict.reason,
        "findings": [
            {
                "category": h.category.value,
                "detector": h.detector,
                "severity": h.severity.value,
                "title": h.title,
                "regulations": h.regulations,
            }
            for h in sorted(verdict.hits, key=lambda x: -x.severity.rank)[:10]
        ],
    }


def _verdict_headers(verdict: Verdict) -> dict[str, str]:
    headers = {
        "X-Prompt-Scanner-Event": verdict.event_id,
        "X-Prompt-Scanner-Action": verdict.action.value,
        "X-Prompt-Scanner-Severity": verdict.severity.value,
        "X-Prompt-Scanner-Score": str(verdict.risk_score),
    }
    if verdict.action is Action.WARN and verdict.message:
        # Single-line: header values cannot contain newlines.
        headers["X-Prompt-Scanner-Warning"] = " ".join(verdict.message.split())[:900]
    if verdict.action is Action.REDACT:
        headers["X-Prompt-Scanner-Redacted"] = "true"
    return headers


# ---------------------------------------------------------------------------
# Core proxy
# ---------------------------------------------------------------------------


def _identity(request: Request) -> tuple[str | None, str | None, str | None]:
    """Actor identity.

    Prefer explicit headers set by an authenticating hop (an identity-aware
    proxy, or the client itself in a managed deployment). Falling back to the
    API-key fingerprint gives a stable pseudonymous actor rather than nothing,
    which keeps per-user analytics meaningful without an SSO integration.
    """
    actor = request.headers.get("x-scanner-actor")
    dept = request.headers.get("x-scanner-department")
    session = request.headers.get("x-scanner-session")
    if not actor:
        key = request.headers.get("x-api-key") or request.headers.get("authorization") or ""
        if key:
            import hashlib

            actor = "key:" + hashlib.sha256(key.encode()).hexdigest()[:12]
    return actor, dept, session


async def _proxy(
    request: Request,
    session: AsyncSession,
    *,
    provider: str,
    upstream_base: str,
    upstream_path: str,
    scannable: bool,
    error_factory,
) -> Response:
    raw = await request.body()
    client = get_http_client()

    headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_REQUEST}
    verdict: Verdict | None = None
    body_out = raw

    if scannable and raw:
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None

        if isinstance(body, dict):
            found = extract.extract(body)
            new_attachments = found.new_attachments
            # A prompt that is *only* an attachment (no accompanying text) must
            # still be evaluated — an empty new_text check alone would skip it.
            if found.new_text.strip() or new_attachments:
                actor, dept, sess = _identity(request)
                ctx = PromptContext(
                    text=found.new_text,
                    source=f"proxy:{provider}",
                    client_app=request.headers.get("user-agent", "")[:128] or None,
                    provider=provider,
                    model=found.model,
                    actor=actor,
                    actor_department=dept,
                    session_id=sess,
                    src_ip=request.client.host if request.client else None,
                    attachments=[_to_attachment_info(a) for a in new_attachments],
                    metadata={
                        "turns": found.message_count,
                        "streaming": found.streaming,
                        "conversation_chars": len(found.full_text),
                    },
                )
                verdict = await pipeline.evaluate(ctx, session)

                if verdict.action is Action.BLOCK:
                    return error_factory(verdict)

                if verdict.action is Action.REDACT:
                    body_out = _redact_body(body, found, verdict)

    upstream_url = f"{upstream_base.rstrip('/')}/{upstream_path.lstrip('/')}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    upstream = client.build_request(
        request.method, upstream_url, headers=headers, content=body_out
    )
    try:
        response = await client.send(upstream, stream=True)
    except httpx.RequestError as exc:
        log.warning("upstream %s unreachable: %s", provider, exc)
        return JSONResponse(
            status_code=502,
            content={"error": {"message": f"Upstream {provider} unreachable: {exc}",
                               "type": "api_connection_error"}},
        )

    out_headers = {
        k: v for k, v in response.headers.items() if k.lower() not in _STRIP_RESPONSE
    }
    if verdict is not None:
        out_headers.update(_verdict_headers(verdict))

    async def body_iter():
        try:
            async for chunk in response.aiter_raw():
                yield chunk
        finally:
            await response.aclose()

    return StreamingResponse(
        body_iter(),
        status_code=response.status_code,
        headers=out_headers,
        media_type=response.headers.get("content-type"),
    )


def _to_attachment_info(a: extract.Attachment) -> AttachmentInfo:
    return AttachmentInfo(
        kind=a.kind,
        media_type=a.media_type,
        source_type=a.source_type,
        size_bytes=a.size_bytes,
        sha256=a.sha256,
        inspectable=a.inspectable,
        block=a.block,
    )


def _redact_body(body: dict, found: extract.Extracted, verdict: Verdict) -> bytes:
    """Mask sensitive spans slot-by-slot so JSON structure survives."""
    settings = get_settings()
    replacements: dict[str, str] = {}
    for _, text in found.slots:
        if text in replacements or not text.strip():
            continue
        gate = fastgate.run(text, evidence_chars=settings.evidence_context_chars)
        masked, count = redact.redact(text, gate.hits)
        if count:
            replacements[text] = masked
    extract.apply_redactions(body, found.slots, replacements)
    return json.dumps(body).encode()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

_ANTHROPIC_SCANNED = {"v1/messages", "v1/messages/count_tokens"}
_OPENAI_SCANNED = {
    "v1/chat/completions", "v1/responses", "v1/completions", "v1/embeddings",
    "chat/completions", "responses", "completions", "embeddings",
}


@router.api_route(
    "/anthropic/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
)
async def anthropic_proxy(
    path: str, request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    return await _proxy(
        request,
        session,
        provider="anthropic",
        upstream_base=get_settings().anthropic_base_url,
        upstream_path=path,
        scannable=path.strip("/") in _ANTHROPIC_SCANNED,
        error_factory=_anthropic_error,
    )


@router.api_route("/openai/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def openai_proxy(
    path: str, request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    return await _proxy(
        request,
        session,
        provider="openai",
        upstream_base=get_settings().openai_base_url,
        upstream_path=path,
        scannable=path.strip("/") in _OPENAI_SCANNED,
        error_factory=_openai_error,
    )
