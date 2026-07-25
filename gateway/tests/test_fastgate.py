from app.detect import fastgate
from app.models import Category, Severity


def detectors(result):
    return {h.detector for h in result.hits}


def test_benign_prompt_scores_zero():
    r = fastgate.run("What's the difference between TCP and UDP?")
    assert r.score == 0
    assert r.severity == Severity.NONE
    assert r.hits == []


def test_aws_secret_key_blocks_at_critical():
    r = fastgate.run(
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    )
    assert r.severity == Severity.CRITICAL
    assert "aws_secret_access_key" in detectors(r)


def test_anthropic_api_key_detected():
    r = fastgate.run("here's my key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789")
    assert "anthropic_api_key" in detectors(r)
    assert r.severity == Severity.CRITICAL


def test_ssn_requires_context_to_avoid_false_positives():
    # A 9-digit number alone (no SSN-like context nearby) should not fire —
    # this is the whole point of context-gated rules: without it, order
    # numbers and phone-like strings would flood the fast gate with noise.
    r = fastgate.run("Invoice total: 219099999 units shipped this quarter")
    assert "us_ssn" not in detectors(r)

    r2 = fastgate.run("Customer SSN is 219-09-9999, please process the refund")
    assert "us_ssn" in detectors(r2)
    assert r2.severity == Severity.CRITICAL


def test_ssn_checksum_rejects_invalid_area():
    # Area 000 is never issued by the SSA — the Luhn-style structural
    # validator should reject it even with SSN context present.
    r = fastgate.run("Their SSN is 000-12-3456 on file")
    assert "us_ssn" not in detectors(r)


def test_payment_card_luhn_validated():
    valid = fastgate.run("Card number 4539578763621486 exp 04/27")
    assert "payment_card" in detectors(valid)
    assert valid.severity == Severity.CRITICAL

    invalid = fastgate.run("Card number 4539578763621480 exp 04/27")
    assert "payment_card" not in detectors(invalid)


def test_known_test_card_is_demoted_not_dropped():
    r = fastgate.run("Use test card 4111111111111111 for the sandbox")
    hit = next(h for h in r.hits if h.detector == "payment_card")
    # Still visible (transparency), but not critical (it's Stripe/Visa's
    # published test number, not a real cardholder's PAN).
    assert hit.severity.rank < Severity.CRITICAL.rank
    assert "test" in (hit.detail or "").lower() or "demoted" in (hit.detail or "").lower()


def test_documentation_email_is_demoted():
    r = fastgate.run("Reach out to admin@example.com for the demo account")
    hit = next(h for h in r.hits if h.detector == "email_address")
    assert hit.severity.rank <= Severity.LOW.rank


def test_phi_identifier_combination_escalates():
    r = fastgate.run(
        "Patient MRN 4471902, DOB 1974-03-11, diagnosis E11.9 type 2 diabetes."
    )
    assert r.severity == Severity.CRITICAL
    assert "combo_identified_health_data" in detectors(r)
    assert any(h.category == Category.PHI for h in r.hits)


def test_confidential_marking_plus_source_code_escalates():
    text = (
        "CONFIDENTIAL - INTERNAL ONLY.\n"
        "package com.northwind.pricing;\n"
        "CREATE TABLE margin_tiers (id int, tier varchar);"
    )
    r = fastgate.run(text)
    assert "combo_marked_source_disclosure" in detectors(r)
    assert r.severity == Severity.CRITICAL


def test_ai_act_prohibited_emotion_recognition_topic_rule():
    r = fastgate.run(
        "Build a model that scores each employee's engagement using emotion "
        "recognition from their webcam during standups."
    )
    assert "ai_act_emotion_recognition" in detectors(r)
    hit = next(h for h in r.hits if h.detector == "ai_act_emotion_recognition")
    assert hit.severity == Severity.CRITICAL


def test_bulk_pii_paste_triggers_volume_escalation():
    rows = "\n".join(f"user{i}@northwind.co.uk" for i in range(60))
    r = fastgate.run("Customer export:\n" + rows)
    assert any(h.detector.startswith("bulk_") for h in r.hits)
    assert r.severity == Severity.CRITICAL


def test_single_confident_critical_hit_sets_severity_floor():
    # A lone critical finding must not be diluted by score averaging across
    # many low-severity hits in the same prompt.
    noise = " ".join(f"contact{i}@example.com" for i in range(3))
    r = fastgate.run(f"{noise} also here is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789")
    assert r.severity == Severity.CRITICAL


def test_fast_gate_runs_in_low_single_digit_milliseconds():
    text = "Ordinary business email about scheduling a meeting next week. " * 50
    r = fastgate.run(text)
    assert r.elapsed_ms < 20
