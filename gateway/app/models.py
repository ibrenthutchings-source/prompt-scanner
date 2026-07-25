"""Persistence model.

Three tables carry the whole audit trail:

  scan_events   one row per prompt that entered the gateway
  findings      one row per detector or council hit on that prompt
  council_votes one row per specialist agent opinion (the "why" behind a verdict)

Raw prompt text is *not* stored by default (see settings.store_raw_prompts) —
the evidence column keeps a bounded, redacted excerpt instead.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class Severity(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Action(str, enum.Enum):
    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"


class Stage(str, enum.Enum):
    """Which layer produced a finding."""

    FAST_GATE = "fast_gate"
    COUNCIL = "council"


class Category(str, enum.Enum):
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    SECRET = "secret"
    IP = "ip"  # trade secrets, source code, unreleased product info
    REGULATED = "regulated"  # EU AI Act / GDPR / sector-specific exposure
    OTHER = "other"


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    # --- provenance --------------------------------------------------------
    source: Mapped[str] = mapped_column(String(32), index=True)  # proxy:anthropic, extension...
    client_app: Mapped[str | None] = mapped_column(String(128))  # cursor, chatgpt-web, ...
    provider: Mapped[str | None] = mapped_column(String(64))  # anthropic, openai
    model: Mapped[str | None] = mapped_column(String(128))
    actor: Mapped[str | None] = mapped_column(String(256), index=True)  # user identity
    actor_department: Mapped[str | None] = mapped_column(String(128), index=True)
    session_id: Mapped[str | None] = mapped_column(String(128), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64))

    # --- content -----------------------------------------------------------
    prompt_chars: Mapped[int] = mapped_column(Integer, default=0)
    prompt_sha256: Mapped[str] = mapped_column(String(64), index=True)
    raw_prompt: Mapped[str | None] = mapped_column(Text)  # only if store_raw_prompts

    # --- verdict -----------------------------------------------------------
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, native_enum=False), default=Severity.NONE, index=True
    )
    action: Mapped[Action] = mapped_column(
        Enum(Action, native_enum=False), default=Action.ALLOW, index=True
    )
    action_reason: Mapped[str | None] = mapped_column(Text)
    council_status: Mapped[str] = mapped_column(String(24), default="skipped", index=True)
    council_summary: Mapped[str | None] = mapped_column(Text)
    # Set when the async council escalated after the request was already allowed.
    retro_escalated: Mapped[bool] = mapped_column(default=False, index=True)

    fast_gate_ms: Mapped[float] = mapped_column(Float, default=0.0)
    council_ms: Mapped[float] = mapped_column(Float, default=0.0)
    council_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)

    acknowledged_by: Mapped[str | None] = mapped_column(String(256))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    analyst_note: Mapped[str | None] = mapped_column(Text)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="event", cascade="all, delete-orphan", lazy="selectin"
    )
    votes: Mapped[list["CouncilVote"]] = relationship(
        back_populates="event", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_scan_events_created_severity", "created_at", "severity"),
        Index("ix_scan_events_actor_created", "actor", "created_at"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("scan_events.id", ondelete="CASCADE"), index=True
    )
    stage: Mapped[Stage] = mapped_column(Enum(Stage, native_enum=False), index=True)
    category: Mapped[Category] = mapped_column(Enum(Category, native_enum=False), index=True)
    detector: Mapped[str] = mapped_column(String(96), index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    score: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str | None] = mapped_column(Text)
    # Redacted excerpt showing where the hit landed.
    evidence: Mapped[str | None] = mapped_column(Text)
    start: Mapped[int | None] = mapped_column(Integer)
    end: Mapped[int | None] = mapped_column(Integer)
    # e.g. ["GDPR Art.9", "EU AI Act Art.5"]
    regulations: Mapped[list[str]] = mapped_column(JSON, default=list)

    event: Mapped[ScanEvent] = relationship(back_populates="findings")


class CouncilVote(Base):
    __tablename__ = "council_votes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("scan_events.id", ondelete="CASCADE"), index=True
    )
    agent: Mapped[str] = mapped_column(String(64), index=True)
    model: Mapped[str] = mapped_column(String(128))
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    rationale: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)

    event: Mapped[ScanEvent] = relationship(back_populates="votes")
