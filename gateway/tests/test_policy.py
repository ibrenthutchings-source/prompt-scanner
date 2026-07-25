import pytest

from app.detect import fastgate
from app.models import Action
from app.policy.engine import PolicyEngine
from app.schemas import PromptContext


@pytest.fixture
def engine():
    # Exercise the actual shipped policy.yaml — this is what a security team
    # edits, so the tests should catch a bad edit to that file, not just to
    # the engine code.
    return PolicyEngine()


def _ctx(**kwargs) -> PromptContext:
    defaults = dict(text="placeholder", source="proxy:anthropic", provider="anthropic")
    defaults.update(kwargs)
    return PromptContext(**defaults)


def test_live_credential_blocks_and_is_not_exemptable(engine):
    ctx = _ctx(text="my key is AKIAIOSFODNN7EXAMPLE", actor_department="security")
    gate = fastgate.run(ctx.text)
    decision = engine.evaluate(ctx, gate.hits, gate.score, gate.severity)
    assert decision.action == Action.BLOCK
    assert decision.rule == "live-credentials"
    # Security dept exemption exists in policy.yaml but must not apply here —
    # exemptable: false on this rule is what the whole "no exceptions for
    # credentials" guarantee rests on.
    assert decision.exemption is None


def test_identified_ssn_is_redacted_not_blocked(engine):
    ctx = _ctx(text="Customer SSN is 219-09-9999, format a support ticket")
    gate = fastgate.run(ctx.text)
    decision = engine.evaluate(ctx, gate.hits, gate.score, gate.severity)
    assert decision.action == Action.REDACT


def test_identified_phi_blocks(engine):
    ctx = _ctx(text="Patient MRN 4471902, DOB 1974-03-11, diagnosis E11.9 diabetes.")
    gate = fastgate.run(ctx.text)
    decision = engine.evaluate(ctx, gate.hits, gate.score, gate.severity)
    assert decision.action == Action.BLOCK
    assert decision.rule == "identified-phi"


def test_benign_prompt_allows(engine):
    ctx = _ctx(text="Explain the CAP theorem in distributed systems.")
    gate = fastgate.run(ctx.text)
    decision = engine.evaluate(ctx, gate.hits, gate.score, gate.severity)
    assert decision.action == Action.ALLOW


def test_security_department_exemption_softens_ip_finding(engine):
    # Marking + source code together escalate to a CRITICAL combo finding
    # (see test_fastgate.py::test_confidential_marking_plus_source_code_escalates) —
    # that's the case this policy rule ("marked-confidential-material",
    # min_severity: critical) actually exists to catch.
    text = (
        "CONFIDENTIAL - INTERNAL ONLY.\n"
        "package com.northwind.pricing;\n"
        "CREATE TABLE margin_tiers (id int, tier varchar);"
    )
    ctx_eng = _ctx(text=text, actor_department="engineering")
    ctx_sec = _ctx(text=text, actor_department="security")
    gate = fastgate.run(text)

    eng_decision = engine.evaluate(ctx_eng, gate.hits, gate.score, gate.severity)
    sec_decision = engine.evaluate(ctx_sec, gate.hits, gate.score, gate.severity)

    # Same content, different department: security's IP exemption caps the
    # action at warn even though engineering gets blocked.
    assert eng_decision.action == Action.BLOCK
    assert sec_decision.action == Action.WARN
    assert sec_decision.exemption == "security-research"


def test_exemption_never_escalates_only_softens(engine):
    # An exemption's max_action must never make an outcome *stricter* than
    # the base decision — it's a ceiling, not a floor.
    ctx = _ctx(text="hello", actor_department="security")
    gate = fastgate.run(ctx.text)
    decision = engine.evaluate(ctx, gate.hits, gate.score, gate.severity)
    assert decision.action == Action.ALLOW


def test_message_template_substitutes_event_id(engine):
    ctx = _ctx(text="my key is AKIAIOSFODNN7EXAMPLE")
    gate = fastgate.run(ctx.text)
    decision = engine.evaluate(ctx, gate.hits, gate.score, gate.severity)
    rendered = decision.message.replace("{event_id}", "evt_test123")
    assert "evt_test123" in rendered
    assert "{event_id}" not in rendered
