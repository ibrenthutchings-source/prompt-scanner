"""Masking for the REDACT enforcement tier.

The goal is to keep the prompt useful. A support engineer asking "why did this
request 500?" with a bearer token in the stack trace should get an answer — with
the token replaced by a stable placeholder, not with the whole prompt refused.

Placeholders are stable per distinct value within one prompt, so a model can
still reason about "the same customer appears in both rows".
"""

from __future__ import annotations

import re

from app.models import Category
from app.schemas import DetectionHit

# Categories whose values are masked. IP and regulated findings are usually
# whole-paragraph concerns; masking a span there produces nonsense, so those
# tiers block or warn instead.
_MASKABLE = {Category.PII, Category.PHI, Category.PCI, Category.SECRET}

_LABELS = {
    Category.PII: "PII",
    Category.PHI: "PHI",
    Category.PCI: "CARD",
    Category.SECRET: "SECRET",
}


def redact(text: str, hits: list[DetectionHit]) -> tuple[str, int]:
    """Returns (redacted_text, spans_masked)."""
    spans: list[tuple[int, int, DetectionHit]] = [
        (h.start, h.end, h)
        for h in hits
        if h.category in _MASKABLE and h.start is not None and h.end is not None
    ]

    # Council findings carry a quoted excerpt instead of offsets. Locate it.
    for hit in hits:
        if hit.category not in _MASKABLE or hit.start is not None:
            continue
        if not hit.evidence or len(hit.evidence) < 4:
            continue
        for match in re.finditer(re.escape(hit.evidence), text):
            spans.append((match.start(), match.end(), hit))

    if not spans:
        return text, 0

    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged: list[tuple[int, int, DetectionHit]] = []
    for start, end, hit in spans:
        if merged and start < merged[-1][1]:
            # Overlapping — extend the existing span, keep the first label.
            p_start, p_end, p_hit = merged[-1]
            merged[-1] = (p_start, max(p_end, end), p_hit)
            continue
        merged.append((start, end, hit))

    placeholders: dict[str, str] = {}
    counters: dict[str, int] = {}
    out: list[str] = []
    cursor = 0

    for start, end, hit in merged:
        out.append(text[cursor:start])
        value = text[start:end]
        if value not in placeholders:
            label = _LABELS.get(hit.category, "REDACTED")
            counters[label] = counters.get(label, 0) + 1
            placeholders[value] = f"[{label}_{counters[label]}_REDACTED]"
        out.append(placeholders[value])
        cursor = end

    out.append(text[cursor:])
    return "".join(out), len(merged)


def redactable(hits: list[DetectionHit]) -> bool:
    """True when masking would actually remove the risk.

    If the only findings are IP or regulated-use concerns, redaction is theatre:
    there is no span to mask, and the policy should warn or block instead.
    """
    return any(
        h.category in _MASKABLE and (h.start is not None or h.evidence) for h in hits
    )
