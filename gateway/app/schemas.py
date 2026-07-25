"""Pydantic contracts: internal pipeline objects + public API shapes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_serializer

from app.models import Action, Category, Severity, Stage

# ---------------------------------------------------------------------------
# Internal pipeline
# ---------------------------------------------------------------------------


class DetectionHit(BaseModel):
    """A single detector or council hit, before it becomes a Finding row."""

    stage: Stage
    category: Category
    detector: str
    severity: Severity
    confidence: float = 1.0
    score: int = 0
    title: str
    detail: str | None = None
    evidence: str | None = None
    start: int | None = None
    end: int | None = None
    regulations: list[str] = Field(default_factory=list)


class AttachmentInfo(BaseModel):
    """One image/PDF attached to the prompt.

    `block` carries the raw Claude-API-shaped content block (image or document)
    when the attachment is small enough and a recognised media type — it is
    forwarded to council specialists for vision review. When absent (a Files
    API reference we can't resolve, or an unsupported media type), the
    attachment still shows up as an unscanned-attachment finding, honestly
    flagging what the gateway could not inspect rather than staying silent.
    """

    kind: Literal["image", "document"]
    media_type: str | None = None
    source_type: str | None = None
    size_bytes: int = 0
    sha256: str = ""
    inspectable: bool = False
    block: dict[str, Any] | None = None


class PromptContext(BaseModel):
    """Everything the pipeline knows about one prompt."""

    text: str
    source: str = "api"
    client_app: str | None = None
    provider: str | None = None
    model: str | None = None
    actor: str | None = None
    actor_department: str | None = None
    session_id: str | None = None
    src_ip: str | None = None
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    # Free-form hints from the caller, e.g. {"repo": "core-pricing"}.
    metadata: dict[str, Any] = Field(default_factory=dict)


class Verdict(BaseModel):
    event_id: str
    action: Action
    severity: Severity
    risk_score: int
    reason: str
    # User-facing text. This is what gets rendered in the error the employee
    # sees, so it is written for them, not for a log.
    message: str = ""
    hits: list[DetectionHit] = Field(default_factory=list)
    redacted_text: str | None = None
    council_status: str = "skipped"
    council_summary: str | None = None
    fast_gate_ms: float = 0.0


# ---------------------------------------------------------------------------
# Council structured output (what each specialist agent returns)
# ---------------------------------------------------------------------------


class CouncilFinding(BaseModel):
    category: Literal["pii", "phi", "pci", "secret", "ip", "regulated", "other"]
    severity: Literal["none", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    rationale: str
    quoted_span: str = Field(
        default="",
        description="Short verbatim excerpt of the offending text, max 60 chars.",
    )
    regulations: list[str] = Field(
        default_factory=list,
        description="Specific citations, e.g. 'GDPR Art. 9(1)', 'EU AI Act Art. 5(1)(a)'.",
    )


class SpecialistOpinion(BaseModel):
    """Structured output contract for every council specialist."""

    severity: Literal["none", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(description="One or two sentences on what you found and why it matters.")
    findings: list[CouncilFinding] = Field(default_factory=list)


class AdjudicatorVerdict(BaseModel):
    """Structured output contract for the adjudicating agent."""

    severity: Literal["none", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: Literal["allow", "warn", "redact", "block"]
    summary: str = Field(description="What a CISO analyst needs to know, in 1-3 sentences.")
    dissent: str = Field(
        default="",
        description="Where specialists disagreed and how you resolved it. Empty if unanimous.",
    )
    false_positive_risk: Literal["low", "medium", "high"] = "medium"
    confirmed_findings: list[CouncilFinding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """POST /v1/scan — used by the browser extension and any direct integration."""

    text: str
    source: str = "extension"
    client_app: str | None = None
    provider: str | None = None
    model: str | None = None
    actor: str | None = None
    actor_department: str | None = None
    session_id: str | None = None
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Wait for the council instead of returning on the fast gate alone.
    wait_for_council: bool = False


class ScanResponse(BaseModel):
    event_id: str
    action: Action
    severity: Severity
    risk_score: int
    reason: str
    message: str
    findings: list[DetectionHit]
    redacted_text: str | None = None
    council_status: str
    council_summary: str | None = None
    fast_gate_ms: float


class FindingOut(BaseModel):
    id: str
    stage: Stage
    category: Category
    detector: str
    severity: Severity
    confidence: float
    score: int
    title: str
    detail: str | None
    evidence: str | None
    regulations: list[str]

    model_config = {"from_attributes": True}


class VoteOut(BaseModel):
    id: str
    agent: str
    model: str
    severity: Severity
    confidence: float
    rationale: str | None
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    error: str | None

    model_config = {"from_attributes": True}


class EventOut(BaseModel):
    id: str
    created_at: datetime
    source: str
    client_app: str | None
    provider: str | None
    model: str | None
    actor: str | None
    actor_department: str | None
    session_id: str | None
    prompt_chars: int
    risk_score: int
    severity: Severity
    action: Action
    action_reason: str | None
    council_status: str
    council_summary: str | None
    retro_escalated: bool
    fast_gate_ms: float
    council_ms: float
    council_cost_usd: float
    acknowledged_by: str | None
    acknowledged_at: datetime | None
    analyst_note: str | None

    model_config = {"from_attributes": True}

    # SQLite drops tzinfo on round-trip even with DateTime(timezone=True), so a
    # naive value here is always UTC wall-clock (every write goes through
    # models.utcnow()). Force an explicit offset on the way out — otherwise
    # the browser's Date parser treats the bare ISO string as *local* time and
    # every timestamp in the UI renders hours off (backwards or forwards
    # depending on the viewer's own timezone).
    @field_serializer("created_at", "acknowledged_at")
    def _serialize_utc(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        else:
            value = value.astimezone(timezone.utc)
        return value.isoformat()


class EventDetailOut(EventOut):
    findings: list[FindingOut] = Field(default_factory=list)
    votes: list[VoteOut] = Field(default_factory=list)
    raw_prompt: str | None = None


class AcknowledgeRequest(BaseModel):
    acknowledged_by: str
    note: str | None = None
