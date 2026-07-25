"""Stage 1: deterministic inline detection.

Runs in the request path, so it must stay fast and allocation-light. Target is
sub-50ms on a 20KB prompt; the rule set is compiled once at import.

Design notes:
  * Context gating is what makes this usable. A bare 9-digit regex on a codebase
    fires constantly; the same regex within 160 chars of "ssn" almost never does.
  * Overlapping hits collapse to the highest-scoring rule so one credit card
    does not also register as a phone number and an MRN.
  * Scoring uses per-category diminishing returns: ten emails are worse than
    one, but not ten times worse. Pasting a whole CRM export should saturate,
    not overflow into meaninglessness.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from app.detect.patterns import PATTERN_RULES, TOPIC_RULES, PatternRule, TopicRule
from app.models import Category, Severity, Stage
from app.schemas import DetectionHit

# Score at which each severity band begins.
SEVERITY_THRESHOLDS: list[tuple[int, Severity]] = [
    (70, Severity.CRITICAL),
    (40, Severity.HIGH),
    (20, Severity.MEDIUM),
    (8, Severity.LOW),
    (0, Severity.NONE),
]

# Nth occurrence of the same rule contributes score * DECAY**(n-1).
_DECAY = 0.45
_MAX_HITS_PER_RULE = 25
_MAX_TOTAL_SCORE = 100


@dataclass
class FastGateResult:
    hits: list[DetectionHit]
    score: int
    severity: Severity
    elapsed_ms: float

    @property
    def categories(self) -> set[Category]:
        return {h.category for h in self.hits}


def _mask(value: str) -> str:
    """Keep enough shape to be recognisable, not enough to be usable."""
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 10:
        return value[0] + "*" * (len(value) - 2) + value[-1]
    return value[:3] + "*" * 8 + value[-2:]


def _evidence(text: str, start: int, end: int, value: str, window: int) -> str:
    if window <= 0:
        return _mask(value)
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    excerpt = text[lo:start] + _mask(value) + text[end:hi]
    return (prefix + re.sub(r"\s+", " ", excerpt).strip() + suffix)[:400]


def _has_context(lowered: str, start: int, end: int, keywords: tuple[str, ...], window: int) -> bool:
    if not keywords:
        return True
    lo = max(0, start - window)
    hi = min(len(lowered), end + window)
    scope = lowered[lo:hi]
    return any(k in scope for k in keywords)


_SEV_ORDER = [Severity.NONE, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _demote(sev: Severity) -> Severity:
    """Known test/sample data: keep it visible, stop it paging anyone."""
    return Severity.LOW if sev.rank >= Severity.MEDIUM.rank else Severity.NONE


def _step_down(sev: Severity) -> Severity:
    return _SEV_ORDER[max(0, _SEV_ORDER.index(sev) - 1)]


def _max_sev(a: Severity, b: Severity) -> Severity:
    return a if a.rank >= b.rank else b


def _run_pattern_rule(
    rule: PatternRule, text: str, lowered: str, evidence_chars: int
) -> tuple[list[tuple[int, int, DetectionHit]], int]:
    """Returns (spans, total_valid_matches). The count outlives the span cap so
    a 400-row CRM paste is distinguishable from a single stray email."""
    out: list[tuple[int, int, DetectionHit]] = []
    valid = 0
    for match in rule.pattern.finditer(text):
        try:
            value = match.group(rule.value_group)
        except (IndexError, re.error):  # pragma: no cover - misconfigured rule
            value = match.group(0)
        if not value:
            continue
        start, end = match.span(rule.value_group if rule.value_group else 0)

        if rule.validator is not None and not rule.validator(value):
            continue
        if not _has_context(lowered, start, end, rule.require_context, rule.context_window):
            continue

        valid += 1
        if valid > _MAX_HITS_PER_RULE:
            continue  # keep counting, stop materialising

        severity = rule.severity
        score = rule.score
        detail = rule.description or None
        if rule.demoter is not None and rule.demoter(value):
            severity = _demote(severity)
            score = max(1, score // 5)
            detail = f"{detail + ' ' if detail else ''}Demoted: {rule.demote_note}."

        out.append(
            (
                start,
                end,
                DetectionHit(
                    stage=Stage.FAST_GATE,
                    category=rule.category,
                    detector=rule.name,
                    severity=severity,
                    confidence=0.95 if rule.validator else 0.75,
                    score=score,
                    title=rule.title,
                    detail=detail,
                    evidence=_evidence(text, start, end, value, evidence_chars),
                    start=start,
                    end=end,
                    regulations=list(rule.regulations),
                ),
            )
        )
    return out, valid


def _run_topic_rule(rule: TopicRule, lowered: str) -> DetectionHit | None:
    triggered = next((t for t in rule.triggers if t in lowered), None)
    if triggered is None:
        return None
    if any(n in lowered for n in rule.negations):
        return None
    if rule.min_support:
        support_hits = sum(1 for s in rule.support if s in lowered)
        if support_hits < rule.min_support:
            return None
    idx = lowered.find(triggered)
    return DetectionHit(
        stage=Stage.FAST_GATE,
        category=rule.category,
        detector=rule.name,
        severity=rule.severity,
        confidence=0.6,
        score=rule.score,
        title=rule.title,
        detail=rule.description or None,
        evidence=f"…{lowered[max(0, idx - 60):idx + len(triggered) + 60].strip()}…",
        start=idx,
        end=idx + len(triggered),
        regulations=list(rule.regulations),
    )


def _dedupe_overlaps(
    spans: list[tuple[int, int, DetectionHit]],
) -> list[DetectionHit]:
    """Highest score wins an overlapping region; ties break on span length."""
    spans.sort(key=lambda s: (-s[2].score, -(s[1] - s[0]), s[0]))
    kept: list[tuple[int, int, DetectionHit]] = []
    for start, end, hit in spans:
        if any(start < k_end and end > k_start for k_start, k_end, _ in kept):
            continue
        kept.append((start, end, hit))
    kept.sort(key=lambda s: s[0])
    return [h for _, _, h in kept]


def score_hits(hits: list[DetectionHit]) -> int:
    """Aggregate with per-detector decay, then cap."""
    seen: dict[str, int] = {}
    total = 0.0
    for hit in sorted(hits, key=lambda h: -h.score):
        n = seen.get(hit.detector, 0)
        total += hit.score * (_DECAY**n) * hit.confidence
        seen[hit.detector] = n + 1
    return int(min(_MAX_TOTAL_SCORE, round(total)))


def severity_for_score(score: int) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.NONE


def run(text: str, evidence_chars: int = 80) -> FastGateResult:
    started = time.perf_counter()
    if not text or not text.strip():
        return FastGateResult([], 0, Severity.NONE, 0.0)

    lowered = text.lower()

    spans: list[tuple[int, int, DetectionHit]] = []
    counts: dict[str, int] = {}
    for rule in PATTERN_RULES:
        rule_spans, total = _run_pattern_rule(rule, text, lowered, evidence_chars)
        spans.extend(rule_spans)
        if total:
            counts[rule.name] = total

    hits = _dedupe_overlaps(spans)

    for topic in TOPIC_RULES:
        hit = _run_topic_rule(topic, lowered)
        if hit is not None:
            hits.append(hit)

    hits.extend(_ner_hits(text, evidence_chars))
    hits.extend(_volume_hits(hits, counts))
    hits = _apply_combination_rules(hits)

    score = score_hits(hits)
    severity = _max_sev(severity_for_score(score), _severity_floor(hits))
    elapsed = (time.perf_counter() - started) * 1000
    return FastGateResult(hits, score, severity, elapsed)


def _severity_floor(hits: list[DetectionHit]) -> Severity:
    """A single confident critical finding must not be averaged away.

    Score aggregation answers "how much exposure"; the floor answers "is any one
    thing bad enough to matter on its own". Low-confidence hits are stepped down
    one band so a fuzzy topic match cannot page anyone at 3am by itself.
    """
    floor = Severity.NONE
    for hit in hits:
        sev = hit.severity if hit.confidence >= 0.7 else _step_down(hit.severity)
        floor = _max_sev(floor, sev)
    return floor


def _volume_hits(hits: list[DetectionHit], counts: dict[str, int]) -> list[DetectionHit]:
    """Bulk repetition of one identifier type is a data-set paste, not a mention."""
    out: list[DetectionHit] = []
    by_detector = {h.detector: h for h in hits}
    for detector, total in counts.items():
        if total < 10:
            continue
        sample = by_detector.get(detector)
        if sample is None:
            continue
        severity = Severity.CRITICAL if total >= 50 else Severity.HIGH
        out.append(
            DetectionHit(
                stage=Stage.FAST_GATE,
                category=sample.category,
                detector=f"bulk_{detector}",
                severity=severity,
                confidence=0.95,
                score=30 if total >= 50 else 20,
                title=f"Bulk disclosure: {total} × {sample.title.lower()}",
                detail=f"{total} distinct matches in one prompt. This is a data-set paste, "
                "not an incidental mention, and is likely reportable in its own right.",
                regulations=sample.regulations,
            )
        )
    return out


def _apply_combination_rules(hits: list[DetectionHit]) -> list[DetectionHit]:
    """Escalations that only make sense across detectors.

    A source-code paste is mundane. A source-code paste inside a document marked
    CONFIDENTIAL is an IP exfiltration event. Same for a name plus a diagnosis:
    individually weak, jointly a HIPAA identifier set.
    """
    detectors = {h.detector for h in hits}
    extra: list[DetectionHit] = []

    if "classification_marking" in detectors and (
        "proprietary_source_code" in detectors or "sql_schema_dump" in detectors
    ):
        extra.append(
            DetectionHit(
                stage=Stage.FAST_GATE,
                category=Category.IP,
                detector="combo_marked_source_disclosure",
                severity=Severity.CRITICAL,
                confidence=0.9,
                score=35,
                title="Confidentiality-marked technical material",
                detail="Source or schema content appears alongside an explicit "
                "confidentiality marking.",
                regulations=["Trade secret law (DTSA / EU 2016/943)"],
            )
        )

    phi_like = {"gdpr_health_data", "icd10_code", "medical_record_number", "nhs_number"}
    identifier_like = {"email_address", "us_ssn", "date_of_birth", "phone_number", "street_address"}
    if detectors & phi_like and detectors & identifier_like:
        extra.append(
            DetectionHit(
                stage=Stage.FAST_GATE,
                category=Category.PHI,
                detector="combo_identified_health_data",
                severity=Severity.CRITICAL,
                confidence=0.9,
                score=40,
                title="Identifiable health information",
                detail="Health content co-occurs with a direct identifier — this is PHI, "
                "not a de-identified data set.",
                regulations=["HIPAA §164.514", "GDPR Art. 9(1)"],
            )
        )

    return hits + extra


# ---------------------------------------------------------------------------
# Optional NER layer
# ---------------------------------------------------------------------------

_ANALYZER = None
_NER_TRIED = False

# Presidio entity -> (category, severity, score)
_NER_MAP = {
    "PERSON": (Category.PII, Severity.LOW, 6),
    "LOCATION": (Category.PII, Severity.LOW, 4),
    "NRP": (Category.REGULATED, Severity.HIGH, 26),  # nationality/religion/political
    "MEDICAL_LICENSE": (Category.PHI, Severity.HIGH, 24),
    "US_DRIVER_LICENSE": (Category.PII, Severity.HIGH, 26),
    "US_BANK_NUMBER": (Category.PII, Severity.HIGH, 28),
    "CRYPTO": (Category.PII, Severity.MEDIUM, 14),
}


def _get_analyzer():
    """Presidio/spaCy are optional. Absence degrades recall, not correctness."""
    global _ANALYZER, _NER_TRIED
    if _NER_TRIED:
        return _ANALYZER
    _NER_TRIED = True
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore

        _ANALYZER = AnalyzerEngine()
    except Exception:  # ImportError, missing spaCy model, incompatible runtime
        _ANALYZER = None
    return _ANALYZER


def ner_available() -> bool:
    return _get_analyzer() is not None


def _ner_hits(text: str, evidence_chars: int) -> list[DetectionHit]:
    analyzer = _get_analyzer()
    if analyzer is None:
        return []
    try:
        results = analyzer.analyze(text=text, entities=list(_NER_MAP), language="en")
    except Exception:
        return []

    hits: list[DetectionHit] = []
    for r in results:
        if r.score < 0.5 or r.entity_type not in _NER_MAP:
            continue
        category, severity, score = _NER_MAP[r.entity_type]
        value = text[r.start : r.end]
        hits.append(
            DetectionHit(
                stage=Stage.FAST_GATE,
                category=category,
                detector=f"ner_{r.entity_type.lower()}",
                severity=severity,
                confidence=float(r.score),
                score=score,
                title=f"{r.entity_type.replace('_', ' ').title()} (NER)",
                evidence=_evidence(text, r.start, r.end, value, evidence_chars),
                start=r.start,
                end=r.end,
            )
        )
    return hits
