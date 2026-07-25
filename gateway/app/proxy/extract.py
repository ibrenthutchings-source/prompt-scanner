"""Pull scannable text out of provider request bodies, and put redactions back.

A subtlety worth stating plainly: on a multi-turn request the *entire* history
is retransmitted every turn, so a naive scanner re-flags turn 1's content on
every subsequent turn and buries analysts in duplicates.

We resolve it by enforcing on `new_text` — the turns added since the last
assistant reply — because earlier turns were already adjudicated when they were
first sent. `full_text` is still captured and handed to the council as context,
so it can spot payloads split deliberately across turns.

Attachments (images, PDFs) get the same "only the new turn" treatment: only
attachments introduced since the last assistant reply are handed to the
council for vision review. Re-uploading the same attachment across a long
conversation does not re-trigger a review each turn.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

# Media types the council can actually look at (Claude vision + native PDF
# input). Anything else (audio, video, arbitrary binary) is flagged as an
# unscanned attachment rather than silently passed through.
_INSPECTABLE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
_INSPECTABLE_DOC_TYPES = {"application/pdf"}


@dataclass
class Attachment:
    kind: str  # "image" | "document"
    media_type: str | None
    source_type: str | None  # base64 | url | file
    size_bytes: int
    sha256: str
    path: tuple[Any, ...]
    is_new: bool
    # The raw content block, ready to append to a Claude API messages payload
    # for council vision review (base64/url source only — file references are
    # not resolvable from here without another Files API round trip).
    block: dict[str, Any] | None
    inspectable: bool


@dataclass
class Extracted:
    full_text: str
    new_text: str
    message_count: int = 0
    model: str | None = None
    streaming: bool = False
    # (path, text) for every scannable leaf, so redaction can write back in place.
    slots: list[tuple[tuple[Any, ...], str]] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def new_attachments(self) -> list[Attachment]:
        return [a for a in self.attachments if a.is_new]


def _attachment_from_block(block: dict[str, Any], path: tuple[Any, ...]) -> Attachment | None:
    btype = block.get("type")
    if btype not in ("image", "document"):
        return None
    source = block.get("source") or {}
    source_type = source.get("type")

    if source_type == "base64":
        data = source.get("data") or ""
        media_type = source.get("media_type")
        size = len(data) * 3 // 4  # base64 expansion factor, close enough
        digest = hashlib.sha256(data.encode("ascii", errors="ignore")).hexdigest()
    elif source_type == "url":
        media_type = source.get("media_type")
        size = 0
        digest = hashlib.sha256((source.get("url") or "").encode()).hexdigest()
    elif source_type == "file":
        # Files API reference — we don't have the bytes, only the pointer.
        media_type = block.get("media_type")
        size = 0
        digest = hashlib.sha256((source.get("file_id") or "").encode()).hexdigest()
    elif source_type == "text":
        return None  # handled as ordinary scannable text, not an attachment
    else:
        return None

    inspectable_types = _INSPECTABLE_IMAGE_TYPES if btype == "image" else _INSPECTABLE_DOC_TYPES
    inspectable = source_type in ("base64", "url") and (media_type in inspectable_types)

    return Attachment(
        kind=btype,
        media_type=media_type,
        source_type=source_type,
        size_bytes=size,
        sha256=digest,
        path=path,
        is_new=False,  # filled in by caller once turn position is known
        block=block if inspectable else None,
        inspectable=inspectable,
    )


def _content_to_parts(
    content: Any, path: tuple[Any, ...]
) -> tuple[list[tuple[tuple[Any, ...], str]], list[Attachment]]:
    """Flatten a content field into (json_path, text) pairs and attachments."""
    if isinstance(content, str):
        return [(path, content)], []
    if not isinstance(content, list):
        return [], []

    texts: list[tuple[tuple[Any, ...], str]] = []
    attachments: list[Attachment] = []
    for i, block in enumerate(content):
        if isinstance(block, str):
            texts.append((path + (i,), block))
            continue
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype in ("text", "input_text", "output_text") and isinstance(block.get("text"), str):
            texts.append((path + (i, "text"), block["text"]))
        elif btype == "tool_result":
            sub_texts, sub_attach = _content_to_parts(block.get("content"), path + (i, "content"))
            texts.extend(sub_texts)
            attachments.extend(sub_attach)
        elif btype == "document":
            source = block.get("source") or {}
            if source.get("type") == "text" and isinstance(source.get("data"), str):
                texts.append((path + (i, "source", "data"), source["data"]))
            else:
                attachment = _attachment_from_block(block, path + (i,))
                if attachment:
                    attachments.append(attachment)
        elif btype == "image":
            attachment = _attachment_from_block(block, path + (i,))
            if attachment:
                attachments.append(attachment)
    return texts, attachments


def extract(body: dict[str, Any]) -> Extracted:
    """Handles Anthropic Messages, OpenAI Chat Completions, and OpenAI Responses."""
    slots: list[tuple[tuple[Any, ...], str]] = []
    all_attachments: list[Attachment] = []

    # System prompt: Anthropic top-level `system`, or an OpenAI system message.
    system = body.get("system") or body.get("instructions")
    if system is not None:
        sys_texts, _ = _content_to_parts(
            system, ("system",) if "system" in body else ("instructions",)
        )
        slots.extend(sys_texts)

    messages = body.get("messages")
    if not isinstance(messages, list):
        # OpenAI Responses API: `input` may be a bare string or a message list.
        messages = body.get("input")
    if isinstance(messages, str):
        slots.append((("input",), messages))
        messages = []
    if not isinstance(messages, list):
        messages = []

    # Index of the first message in the trailing user block.
    new_from = len(messages)
    for i in range(len(messages) - 1, -1, -1):
        role = messages[i].get("role") if isinstance(messages[i], dict) else None
        if role == "assistant":
            break
        new_from = i

    message_slots: list[tuple[int, tuple[Any, ...], str]] = []
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        parts, attachments = _content_to_parts(message.get("content"), ("messages", i, "content"))
        for path, text in parts:
            message_slots.append((i, path, text))
            slots.append((path, text))
        for attachment in attachments:
            attachment.is_new = i >= new_from
            all_attachments.append(attachment)

    system_text = "\n\n".join(
        t for p, t in slots if p and p[0] in ("system", "instructions")
    )
    full_text = "\n\n".join(t for _, t in slots if t)
    new_text = "\n\n".join(t for i, _, t in message_slots if i >= new_from and t)
    # Single-shot payloads (no assistant turn yet, or a bare `input` string)
    # have no delta — scan everything.
    if not new_text:
        new_text = full_text
    elif system_text and len(messages) <= 1:
        new_text = full_text

    return Extracted(
        full_text=full_text,
        new_text=new_text,
        message_count=len(messages),
        model=body.get("model"),
        streaming=bool(body.get("stream")),
        slots=slots,
        attachments=all_attachments,
    )


def _set_path(body: dict[str, Any], path: tuple[Any, ...], value: str) -> None:
    node: Any = body
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def apply_redactions(
    body: dict[str, Any], slots: list[tuple[tuple[Any, ...], str]], replacements: dict[str, str]
) -> int:
    """Write redacted text back into the request body in place.

    `replacements` maps original slot text -> redacted slot text.
    """
    changed = 0
    for path, original in slots:
        new = replacements.get(original)
        if new is not None and new != original:
            try:
                _set_path(body, path, new)
                changed += 1
            except (KeyError, IndexError, TypeError):
                continue
    return changed
