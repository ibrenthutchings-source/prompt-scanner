"""Deterministic rule catalogue for the fast gate.

Two rule kinds:

  PatternRule  a regex over the prompt, optionally checksum-validated and/or
               gated on nearby context keywords (cuts false positives hard).
  TopicRule    phrase clusters that signal a regulated or proprietary subject
               matter rather than a specific identifier format.

Every rule carries the regulation citations it implicates so the dashboard can
answer "show me everything that touches GDPR Art. 9" without a second mapping.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from app.detect import validators as V
from app.models import Category, Severity


@dataclass(frozen=True)
class PatternRule:
    name: str
    category: Category
    severity: Severity
    score: int
    pattern: re.Pattern[str]
    title: str
    description: str = ""
    # Return True to keep the match, False to drop it.
    validator: Callable[[str], bool] | None = None
    # If set, the match only counts when one of these appears within
    # `context_window` characters either side.
    require_context: tuple[str, ...] = ()
    context_window: int = 160
    regulations: tuple[str, ...] = ()
    # Which regex group holds the sensitive value (for redaction). 0 = whole match.
    value_group: int = 0
    # Downgrade instead of dropping when this returns True (test/sample data).
    demoter: Callable[[str], bool] | None = None
    demote_note: str = "looks like documentation or test data"


@dataclass(frozen=True)
class TopicRule:
    name: str
    category: Category
    severity: Severity
    score: int
    title: str
    # Any one of these phrases triggers the rule.
    triggers: tuple[str, ...]
    # ...but only if at least `min_support` distinct supporting terms co-occur.
    support: tuple[str, ...] = ()
    min_support: int = 0
    description: str = ""
    regulations: tuple[str, ...] = ()
    negations: tuple[str, ...] = field(default_factory=tuple)


def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags | re.IGNORECASE)


# ---------------------------------------------------------------------------
# PII
# ---------------------------------------------------------------------------

PII_RULES: list[PatternRule] = [
    PatternRule(
        name="email_address",
        category=Category.PII,
        severity=Severity.LOW,
        score=8,
        pattern=_rx(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}\b"),
        title="Email address",
        description="Direct identifier under GDPR Art. 4(1).",
        regulations=("GDPR Art. 4(1)", "CCPA §1798.140(v)"),
        demoter=V.is_documentation_email,
    ),
    PatternRule(
        name="us_ssn",
        category=Category.PII,
        severity=Severity.CRITICAL,
        score=45,
        pattern=_rx(r"\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
        title="US Social Security Number",
        validator=V.valid_ssn,
        require_context=(
            "ssn", "social security", "soc sec", "tax id", "taxpayer", "ss#",
            "employee", "patient", "applicant", "customer", "dob", "date of birth",
        ),
        regulations=("GLBA", "US state breach-notification statutes"),
    ),
    PatternRule(
        name="phone_number",
        category=Category.PII,
        severity=Severity.LOW,
        score=6,
        pattern=_rx(
            r"(?<![\w.])(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?|\d{2,4}[\s.\-])"
            r"\d{3}[\s.\-]?\d{3,4}(?![\w.])"
        ),
        title="Telephone number",
        require_context=(
            "phone", "tel", "mobile", "cell", "contact", "call", "fax", "whatsapp",
        ),
        regulations=("GDPR Art. 4(1)",),
        demoter=V.is_reserved_phone,
    ),
    PatternRule(
        name="iban",
        category=Category.PII,
        severity=Severity.HIGH,
        score=30,
        pattern=_rx(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}\b"),
        title="IBAN bank account",
        validator=V.valid_iban,
        regulations=("GDPR Art. 4(1)", "PSD2"),
    ),
    PatternRule(
        name="uk_nino",
        category=Category.PII,
        severity=Severity.HIGH,
        score=32,
        pattern=_rx(r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?"
                    r"\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"),
        title="UK National Insurance number",
        regulations=("UK GDPR Art. 4(1)", "DPA 2018"),
    ),
    PatternRule(
        name="passport_number",
        category=Category.PII,
        severity=Severity.HIGH,
        score=28,
        pattern=_rx(r"\b[A-Z]{1,2}\d{6,9}\b"),
        title="Passport number",
        require_context=("passport", "travel document", "mrz", "visa application"),
        context_window=90,
        regulations=("GDPR Art. 4(1)",),
    ),
    PatternRule(
        name="date_of_birth",
        category=Category.PII,
        severity=Severity.MEDIUM,
        score=14,
        pattern=_rx(
            r"\b(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])\b"
            r"|\b(?:0?[1-9]|[12]\d|3[01])[-/](?:0?[1-9]|1[0-2])[-/](?:19|20)\d{2}\b"
        ),
        title="Date of birth",
        require_context=("dob", "date of birth", "born", "birthdate", "birth date", "d.o.b"),
        context_window=60,
        regulations=("GDPR Art. 4(1)", "HIPAA §164.514(b)(2)(i)(C)"),
    ),
    PatternRule(
        name="ipv4_public",
        category=Category.PII,
        severity=Severity.LOW,
        score=4,
        pattern=_rx(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        title="IP address",
        description="Online identifier; personal data per GDPR Recital 30 when linkable.",
        validator=lambda m: _is_public_ipv4(m),
        regulations=("GDPR Recital 30",),
    ),
    PatternRule(
        name="street_address",
        category=Category.PII,
        severity=Severity.MEDIUM,
        score=10,
        pattern=_rx(
            r"\b\d{1,5}\s+[A-Z][A-Za-z.'\-]*(?:\s+[A-Z][A-Za-z.'\-]*){0,4}\s+"
            r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|"
            r"way|place|pl|terrace|parkway|pkwy)\b\.?"
        ),
        title="Postal address",
        regulations=("GDPR Art. 4(1)", "HIPAA §164.514(b)(2)(i)(B)"),
    ),
]


# ---------------------------------------------------------------------------
# PCI
# ---------------------------------------------------------------------------

PCI_RULES: list[PatternRule] = [
    PatternRule(
        name="payment_card",
        category=Category.PCI,
        severity=Severity.CRITICAL,
        score=48,
        pattern=_rx(r"\b(?:\d[ \-]?){12,18}\d\b"),
        title="Payment card number",
        validator=V.valid_card,
        regulations=("PCI-DSS 3.4", "GDPR Art. 4(1)"),
        demoter=V.is_test_card,
        demote_note="known payment-provider test card",
    ),
    PatternRule(
        name="card_cvv",
        category=Category.PCI,
        severity=Severity.HIGH,
        score=25,
        pattern=_rx(r"\b\d{3,4}\b"),
        title="Card verification value",
        require_context=("cvv", "cvc", "cid", "security code", "card code"),
        context_window=40,
        regulations=("PCI-DSS 3.2",),
    ),
]


# ---------------------------------------------------------------------------
# PHI
# ---------------------------------------------------------------------------

PHI_RULES: list[PatternRule] = [
    PatternRule(
        name="medical_record_number",
        category=Category.PHI,
        severity=Severity.CRITICAL,
        score=42,
        pattern=_rx(r"\b[A-Z]{0,3}[-\s]?\d{6,12}\b"),
        title="Medical record number",
        require_context=("mrn", "medical record", "chart number", "patient id", "patient no"),
        context_window=60,
        regulations=("HIPAA §164.514(b)(2)(i)(H)",),
    ),
    PatternRule(
        name="npi_number",
        category=Category.PHI,
        severity=Severity.MEDIUM,
        score=16,
        pattern=_rx(r"\b\d{10}\b"),
        title="US National Provider Identifier",
        validator=V.valid_npi,
        require_context=("npi", "provider", "prescriber", "clinician", "physician"),
        context_window=80,
        regulations=("HIPAA §164.514",),
    ),
    PatternRule(
        name="nhs_number",
        category=Category.PHI,
        severity=Severity.CRITICAL,
        score=42,
        pattern=_rx(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b"),
        title="UK NHS number",
        validator=V.valid_nhs,
        require_context=("nhs", "patient", "gp ", "surgery", "trust"),
        context_window=90,
        regulations=("UK GDPR Art. 9", "DPA 2018 Sch. 3"),
    ),
    PatternRule(
        name="icd10_code",
        category=Category.PHI,
        severity=Severity.HIGH,
        score=22,
        pattern=_rx(r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b"),
        title="ICD-10 diagnosis code",
        require_context=("icd", "diagnosis", "dx", "coded", "billing code", "encounter"),
        context_window=100,
        regulations=("HIPAA §164.514", "GDPR Art. 9(1)"),
    ),
]


# ---------------------------------------------------------------------------
# Secrets and credentials
# ---------------------------------------------------------------------------

SECRET_RULES: list[PatternRule] = [
    PatternRule(
        name="aws_access_key_id",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=50,
        pattern=_rx(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        title="AWS access key ID",
    ),
    PatternRule(
        name="aws_secret_access_key",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=55,
        pattern=_rx(
            r"(?:aws.{0,20})?(?:secret|private).{0,20}[\'\"=:\s]([A-Za-z0-9/+=]{40})\b"
        ),
        title="AWS secret access key",
        value_group=1,
    ),
    PatternRule(
        name="github_token",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=50,
        pattern=_rx(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        title="GitHub access token",
    ),
    PatternRule(
        name="anthropic_api_key",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=50,
        pattern=_rx(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        title="Anthropic API key",
    ),
    PatternRule(
        name="openai_api_key",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=50,
        pattern=_rx(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b"),
        title="OpenAI API key",
    ),
    PatternRule(
        name="google_api_key",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=48,
        pattern=_rx(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        title="Google API key",
    ),
    PatternRule(
        name="slack_token",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=48,
        pattern=_rx(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        title="Slack token",
    ),
    PatternRule(
        name="stripe_secret_key",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=52,
        pattern=_rx(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
        title="Stripe live secret key",
    ),
    PatternRule(
        name="private_key_block",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=60,
        pattern=_rx(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        title="Private key material",
    ),
    PatternRule(
        name="jwt",
        category=Category.SECRET,
        severity=Severity.HIGH,
        score=28,
        pattern=_rx(r"\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        title="JSON Web Token",
    ),
    PatternRule(
        name="azure_connection_string",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=50,
        pattern=_rx(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;\s]+"),
        title="Azure storage connection string",
    ),
    PatternRule(
        name="db_connection_uri",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        score=45,
        pattern=_rx(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
            r"[^\s:@/]+:[^\s:@/]+@[^\s/]+"
        ),
        title="Database connection string with credentials",
    ),
    PatternRule(
        name="generic_credential_assignment",
        category=Category.SECRET,
        severity=Severity.HIGH,
        score=30,
        pattern=_rx(
            r"(?:api[_\-]?key|apikey|secret|passwd|password|token|client[_\-]?secret|"
            r"access[_\-]?token|auth[_\-]?token|private[_\-]?key)"
            r"\s*[:=]\s*[\"\']?([A-Za-z0-9+/=_\-\.]{16,})[\"\']?"
        ),
        title="Hardcoded credential assignment",
        value_group=1,
        validator=lambda v: V.looks_like_secret(v, min_len=16, min_entropy=3.2),
    ),
]


# ---------------------------------------------------------------------------
# Intellectual property
# ---------------------------------------------------------------------------

IP_RULES: list[PatternRule] = [
    PatternRule(
        name="classification_marking",
        category=Category.IP,
        severity=Severity.HIGH,
        score=32,
        pattern=_rx(
            r"\b(?:strictly\s+)?(?:company\s+)?confidential(?:\s+(?:and\s+)?proprietary)?\b"
            r"|\binternal\s+(?:use\s+)?only\b"
            r"|\battorney[\s\-]client\s+privileged\b"
            r"|\bdo\s+not\s+(?:distribute|forward|share\s+externally)\b"
            r"|\btrade\s+secret\b"
            r"|\bnda[\s\-]protected\b"
        ),
        title="Document carries a confidentiality marking",
        description="Explicit handling label indicating the content is not for external systems.",
        regulations=("Trade secret law (DTSA / EU 2016/943)",),
    ),
    PatternRule(
        name="internal_repo_reference",
        category=Category.IP,
        severity=Severity.MEDIUM,
        score=14,
        pattern=_rx(
            r"\bgit@[\w.\-]+:[\w.\-/]+\.git\b"
            r"|\bhttps?://(?:gitlab|git|bitbucket|github)\.[\w.\-]*(?:internal|corp|local)"
            r"[\w.\-]*/[\w.\-/]+"
        ),
        title="Internal source repository reference",
    ),
    PatternRule(
        name="sql_schema_dump",
        category=Category.IP,
        severity=Severity.MEDIUM,
        score=16,
        pattern=_rx(
            r"\bCREATE\s+(?:TABLE|SCHEMA|DATABASE)\s+[`\"\[]?\w+"
            r"|\bALTER\s+TABLE\s+[`\"\[]?\w+\s+ADD\s+(?:CONSTRAINT|COLUMN)"
        ),
        title="Database schema definition",
        description="Schema structure is frequently proprietary and aids attacker recon.",
    ),
    PatternRule(
        name="proprietary_source_code",
        category=Category.IP,
        severity=Severity.MEDIUM,
        score=12,
        pattern=_rx(
            r"^\s*(?:package\s+com\.|import\s+com\.|from\s+\w+\.\w+\s+import|"
            r"#include\s+\"|namespace\s+\w+|@Component|@Service|@Injectable)",
            re.MULTILINE,
        ),
        title="Source code paste",
        description="Low severity alone; escalates when combined with a confidentiality marking.",
    ),
]


# ---------------------------------------------------------------------------
# Topic rules: regulated subject matter and material non-public information
# ---------------------------------------------------------------------------

TOPIC_RULES: list[TopicRule] = [
    # --- GDPR Art. 9 special categories ------------------------------------
    TopicRule(
        name="gdpr_health_data",
        category=Category.PHI,
        severity=Severity.HIGH,
        score=26,
        title="Health data (GDPR special category)",
        triggers=(
            "diagnosis", "diagnosed with", "prognosis", "medical history", "prescription",
            "medication", "chemotherapy", "hiv status", "mental health", "psychiatric",
            "disability status", "blood test", "lab results", "treatment plan",
        ),
        support=("patient", "employee", "customer", "name", "record", "dob", "clinic", "hospital"),
        min_support=1,
        description="Processing health data requires an Art. 9(2) condition; LLM vendors rarely qualify.",
        regulations=("GDPR Art. 9(1)", "HIPAA §164.502"),
    ),
    TopicRule(
        name="gdpr_special_category",
        category=Category.REGULATED,
        severity=Severity.HIGH,
        score=28,
        title="Special-category personal data",
        triggers=(
            "racial origin", "ethnic origin", "religious belief", "political opinion",
            "trade union member", "sexual orientation", "sex life", "genetic data",
            "biometric data", "immigration status", "criminal conviction", "criminal record",
        ),
        description="Art. 9 / Art. 10 data. Prohibited absent an explicit legal basis.",
        regulations=("GDPR Art. 9(1)", "GDPR Art. 10"),
    ),
    # --- EU AI Act Art. 5 prohibited practices ------------------------------
    TopicRule(
        name="ai_act_social_scoring",
        category=Category.REGULATED,
        severity=Severity.CRITICAL,
        score=45,
        title="Possible AI Act Art. 5 prohibited practice: social scoring",
        triggers=(
            "social score", "social scoring", "trustworthiness score", "citizen score",
            "rank citizens", "score individuals based on behaviour",
            "score individuals based on behavior",
        ),
        description="Art. 5(1)(c) bans social scoring leading to detrimental treatment.",
        regulations=("EU AI Act Art. 5(1)(c)",),
    ),
    TopicRule(
        name="ai_act_emotion_recognition",
        category=Category.REGULATED,
        severity=Severity.CRITICAL,
        score=42,
        title="Possible AI Act Art. 5 prohibited practice: emotion inference",
        triggers=(
            "emotion recognition", "infer emotion", "detect emotions", "sentiment of the employee",
            "mood detection", "stress detection from video", "engagement scoring from webcam",
        ),
        support=("employee", "staff", "worker", "candidate", "student", "classroom", "workplace"),
        min_support=1,
        description="Art. 5(1)(f) bans emotion inference in workplace and education contexts.",
        regulations=("EU AI Act Art. 5(1)(f)",),
    ),
    TopicRule(
        name="ai_act_biometric_categorisation",
        category=Category.REGULATED,
        severity=Severity.CRITICAL,
        score=42,
        title="Possible AI Act Art. 5 prohibited practice: biometric categorisation",
        triggers=(
            "facial recognition database", "scrape faces", "untargeted scraping of facial",
            "biometric categorisation", "biometric categorization",
            "infer ethnicity from photo", "predict religion from image",
        ),
        description="Art. 5(1)(e)/(g) ban untargeted facial scraping and sensitive biometric inference.",
        regulations=("EU AI Act Art. 5(1)(e)", "EU AI Act Art. 5(1)(g)"),
    ),
    TopicRule(
        name="ai_act_predictive_policing",
        category=Category.REGULATED,
        severity=Severity.CRITICAL,
        score=42,
        title="Possible AI Act Art. 5 prohibited practice: predictive policing",
        triggers=(
            "predict criminality", "predictive policing", "likelihood of committing a crime",
            "risk of reoffending based on personality", "crime prediction from profile",
        ),
        description="Art. 5(1)(d) bans individual crime prediction based solely on profiling.",
        regulations=("EU AI Act Art. 5(1)(d)",),
    ),
    # --- EU AI Act Annex III high-risk --------------------------------------
    TopicRule(
        name="ai_act_high_risk_employment",
        category=Category.REGULATED,
        severity=Severity.HIGH,
        score=26,
        title="High-risk AI use: employment decisioning",
        triggers=(
            "screen resumes", "screen cvs", "rank candidates", "shortlist applicants",
            "automated hiring decision", "promotion decision", "termination recommendation",
            "performance ranking of employees",
        ),
        description="Annex III(4) high-risk. Requires conformity assessment, logging, human oversight.",
        regulations=("EU AI Act Annex III(4)", "EU AI Act Art. 6"),
    ),
    TopicRule(
        name="ai_act_high_risk_credit",
        category=Category.REGULATED,
        severity=Severity.HIGH,
        score=26,
        title="High-risk AI use: creditworthiness or essential services",
        triggers=(
            "credit score", "creditworthiness", "loan approval decision", "deny the application",
            "insurance pricing for individual", "benefit eligibility decision",
        ),
        support=("applicant", "customer", "individual", "borrower", "claimant"),
        min_support=1,
        description="Annex III(5) high-risk system obligations attach.",
        regulations=("EU AI Act Annex III(5)",),
    ),
    TopicRule(
        name="gdpr_automated_decision",
        category=Category.REGULATED,
        severity=Severity.MEDIUM,
        score=18,
        title="Solely automated decision with legal effect",
        triggers=(
            "automatically reject", "auto-decline the applicant", "decide without human review",
            "no human in the loop", "automated decision-making",
        ),
        description="GDPR Art. 22 restricts solely automated decisions producing legal effects.",
        regulations=("GDPR Art. 22",),
    ),
    TopicRule(
        name="cross_border_transfer",
        category=Category.REGULATED,
        severity=Severity.MEDIUM,
        score=16,
        title="Personal data transfer outside the EEA",
        triggers=(
            "transfer to the us", "transfer outside the eea", "export personal data",
            "standard contractual clauses", "third country transfer",
        ),
        description="Chapter V transfer safeguards must be in place before sending data abroad.",
        regulations=("GDPR Chapter V", "GDPR Art. 44"),
    ),
    # --- Material non-public information ------------------------------------
    TopicRule(
        name="material_nonpublic_info",
        category=Category.IP,
        severity=Severity.HIGH,
        score=30,
        title="Material non-public information",
        triggers=(
            "unannounced acquisition", "pending merger", "before the earnings release",
            "pre-announcement", "quiet period", "term sheet", "letter of intent",
            "unreleased financials", "board deck",
        ),
        support=("confidential", "internal", "draft", "do not share", "embargo"),
        min_support=0,
        description="Insider-trading and disclosure exposure if it leaves the perimeter.",
        regulations=("SEC Reg FD", "EU MAR Art. 10"),
    ),
    TopicRule(
        name="unreleased_product",
        category=Category.IP,
        severity=Severity.MEDIUM,
        score=18,
        title="Unreleased product or roadmap detail",
        triggers=(
            "unreleased", "not yet announced", "roadmap for q", "under embargo",
            "codename", "pre-release build", "internal roadmap",
        ),
        description="Competitive-advantage loss if retained by a third-party model.",
    ),
    TopicRule(
        name="model_training_optout",
        category=Category.REGULATED,
        severity=Severity.MEDIUM,
        score=14,
        title="Content flagged as not for model training",
        triggers=(
            "not for training", "do not train on", "no ai training", "opt out of training",
        ),
        description="Contractual or policy restriction on third-party model retention.",
    ),
]


PATTERN_RULES: list[PatternRule] = [
    *SECRET_RULES,
    *PCI_RULES,
    *PII_RULES,
    *PHI_RULES,
    *IP_RULES,
]


def _is_public_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    # Private, loopback, link-local, multicast, reserved, and version-like strings.
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    return True
