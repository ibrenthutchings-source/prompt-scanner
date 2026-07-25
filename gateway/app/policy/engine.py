"""Policy evaluation: turns findings into an enforcement decision.

Deliberately declarative. A CISO team should be able to change what gets blocked
by editing policy.yaml and hitting the reload endpoint, without a deploy and
without reading Python.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.config import get_settings
from app.models import Action, Category, Severity
from app.schemas import DetectionHit, PromptContext

log = logging.getLogger(__name__)

_ACTION_RANK = {Action.ALLOW: 0, Action.WARN: 1, Action.REDACT: 2, Action.BLOCK: 3}


def _action(value: str) -> Action:
    return Action(value.lower())


def _severity(value: str) -> Severity:
    return Severity(value.lower())


@dataclass
class Rule:
    name: str
    action: Action
    description: str = ""
    message: str = ""
    exemptable: bool = True
    categories: set[Category] = field(default_factory=set)
    detectors: set[str] = field(default_factory=set)
    detector_prefixes: tuple[str, ...] = ()
    min_severity: Severity = Severity.LOW
    sources: set[str] = field(default_factory=set)
    departments: set[str] = field(default_factory=set)
    providers: set[str] = field(default_factory=set)
    min_score: int = 0
    council_action: str | None = None
    min_council_confidence: float = 0.0


@dataclass
class Exemption:
    name: str
    max_action: Action
    description: str = ""
    departments: set[str] = field(default_factory=set)
    actors: set[str] = field(default_factory=set)
    providers: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    applies_to_categories: set[Category] = field(default_factory=set)


@dataclass
class Decision:
    action: Action
    reason: str
    message: str
    rule: str | None = None
    exemption: str | None = None
    matched_hits: list[DetectionHit] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or get_settings().policy_path
        self.version: int = 0
        self.severity_actions: dict[Severity, Action] = {}
        self.messages: dict[str, str] = {}
        self.rules: list[Rule] = []
        self.exemptions: list[Exemption] = []
        self.load()

    # -- loading -----------------------------------------------------------
    def load(self) -> None:
        raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        self.version = int(raw.get("version", 0))
        self.severity_actions = {
            _severity(k): _action(v) for k, v in (raw.get("severity_actions") or {}).items()
        }
        self.messages = raw.get("messages") or {}
        self.rules = [self._parse_rule(r) for r in (raw.get("rules") or [])]
        self.exemptions = [self._parse_exemption(e) for e in (raw.get("exemptions") or [])]
        log.info(
            "policy v%s loaded: %d rules, %d exemptions",
            self.version,
            len(self.rules),
            len(self.exemptions),
        )

    @staticmethod
    def _parse_rule(raw: dict) -> Rule:
        when = raw.get("when") or {}
        return Rule(
            name=raw["name"],
            action=_action(raw["action"]),
            description=raw.get("description", ""),
            message=raw.get("message", ""),
            exemptable=bool(raw.get("exemptable", True)),
            categories={Category(c) for c in when.get("categories", [])},
            detectors=set(when.get("detectors", [])),
            detector_prefixes=tuple(when.get("detector_prefixes", [])),
            min_severity=_severity(when.get("min_severity", "low")),
            sources=set(when.get("sources", [])),
            departments={d.lower() for d in when.get("departments", [])},
            providers={p.lower() for p in when.get("providers", [])},
            min_score=int(when.get("min_score", 0)),
            council_action=when.get("council_action"),
            min_council_confidence=float(when.get("min_council_confidence", 0.0)),
        )

    @staticmethod
    def _parse_exemption(raw: dict) -> Exemption:
        when = raw.get("when") or {}
        return Exemption(
            name=raw["name"],
            max_action=_action(raw["max_action"]),
            description=raw.get("description", ""),
            departments={d.lower() for d in when.get("departments", [])},
            actors={a.lower() for a in when.get("actors", [])},
            providers={p.lower() for p in when.get("providers", [])},
            sources=set(when.get("sources", [])),
            applies_to_categories={Category(c) for c in raw.get("applies_to_categories", [])},
        )

    # -- evaluation --------------------------------------------------------
    def evaluate(
        self,
        ctx: PromptContext,
        hits: list[DetectionHit],
        score: int,
        severity: Severity,
        council_action: str | None = None,
        council_confidence: float = 0.0,
        council_summary: str = "",
    ) -> Decision:
        settings = get_settings()

        matched_rule: Rule | None = None
        matched_hits: list[DetectionHit] = []

        for rule in self.rules:
            hit_subset = self._rule_matches(rule, ctx, hits, score, council_action,
                                            council_confidence)
            if hit_subset is not None:
                matched_rule = rule
                matched_hits = hit_subset
                break

        if matched_rule is not None:
            action = matched_rule.action
            reason = f"rule:{matched_rule.name}"
            template = matched_rule.message or self.messages.get(action.value, "")
            exemptable = matched_rule.exemptable
        else:
            action = self.severity_actions.get(severity, Action.ALLOW)
            reason = f"severity:{severity.value}"
            template = self.messages.get(action.value, "")
            matched_hits = [h for h in hits if h.severity.rank >= Severity.MEDIUM.rank]
            exemptable = True

        exemption_name = None
        if exemptable and action is not Action.ALLOW:
            exemption = self._find_exemption(ctx, matched_hits or hits)
            if exemption and _ACTION_RANK[exemption.max_action] < _ACTION_RANK[action]:
                action = exemption.max_action
                exemption_name = exemption.name
                reason = f"{reason}+exempt:{exemption.name}"
                template = self.messages.get(action.value, "")

        if settings.shadow_mode and action is not Action.ALLOW:
            reason = f"{reason}+shadow_mode"
            action = Action.ALLOW

        return Decision(
            action=action,
            reason=reason,
            message=self._render(template, ctx, matched_hits, council_summary),
            rule=matched_rule.name if matched_rule else None,
            exemption=exemption_name,
            matched_hits=matched_hits,
        )

    def _rule_matches(
        self,
        rule: Rule,
        ctx: PromptContext,
        hits: list[DetectionHit],
        score: int,
        council_action: str | None,
        council_confidence: float,
    ) -> list[DetectionHit] | None:
        """Returns the hits that satisfied the rule, or None if it did not match."""
        if rule.sources and ctx.source not in rule.sources:
            return None
        if rule.departments and (ctx.actor_department or "").lower() not in rule.departments:
            return None
        if rule.providers and (ctx.provider or "").lower() not in rule.providers:
            return None
        if score < rule.min_score:
            return None

        if rule.council_action is not None:
            if council_action != rule.council_action:
                return None
            if council_confidence < rule.min_council_confidence:
                return None
            # Council rules match on the verdict, not on individual hits.
            return [h for h in hits if h.stage.value == "council"] or hits

        selectors = bool(rule.categories or rule.detectors or rule.detector_prefixes)
        if not selectors:
            return hits

        matched = [
            h
            for h in hits
            if h.severity.rank >= rule.min_severity.rank
            and (
                (rule.categories and h.category in rule.categories)
                or (rule.detectors and h.detector in rule.detectors)
                or (
                    rule.detector_prefixes
                    and h.detector.startswith(rule.detector_prefixes)
                )
            )
        ]
        return matched or None

    def _find_exemption(
        self, ctx: PromptContext, hits: list[DetectionHit]
    ) -> Exemption | None:
        dept = (ctx.actor_department or "").lower()
        actor = (ctx.actor or "").lower()
        provider = (ctx.provider or "").lower()
        categories = {h.category for h in hits}

        best: Exemption | None = None
        for ex in self.exemptions:
            if ex.departments and dept not in ex.departments:
                continue
            if ex.actors and actor not in ex.actors:
                continue
            if ex.providers and provider not in ex.providers:
                continue
            if ex.sources and ctx.source not in ex.sources:
                continue
            # An exemption scoped to categories only applies if *every* finding
            # falls inside that scope. One out-of-scope critical voids it.
            if ex.applies_to_categories and not categories <= ex.applies_to_categories:
                continue
            if best is None or _ACTION_RANK[ex.max_action] > _ACTION_RANK[best.max_action]:
                best = ex
        return best

    @staticmethod
    def _render(
        template: str,
        ctx: PromptContext,
        hits: list[DetectionHit],
        council_summary: str,
    ) -> str:
        if not template:
            return ""
        top = sorted(hits, key=lambda h: -h.severity.rank)[:3]
        detectors = ", ".join(dict.fromkeys(h.detector for h in top)) or "policy findings"
        summary = "; ".join(dict.fromkeys(h.title.lower() for h in top)) or "sensitive content"
        try:
            return " ".join(
                template.format(
                    provider=ctx.provider or "the model provider",
                    detectors=detectors,
                    summary=summary,
                    council_summary=council_summary or "",
                    event_id="{event_id}",  # substituted once the row has an id
                ).split()
            )
        except (KeyError, IndexError):
            return " ".join(template.split())


_engine: PolicyEngine | None = None


def get_policy() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine


def reload_policy() -> PolicyEngine:
    engine = get_policy()
    engine.load()
    return engine
