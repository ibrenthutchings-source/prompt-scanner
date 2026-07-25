"""Checksum and heuristic validators.

These exist to keep the fast gate's precision up. A raw 16-digit regex fires on
order numbers and timestamps; a Luhn check does not.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Card numbers that every payment provider publishes as test data. Real, but
# never sensitive — we downgrade rather than drop, because seeing them in a
# prompt still tells you someone is pasting payment payloads around.
TEST_CARDS = {
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "5555555555554444",
    "5105105105105100",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "3530111333300000",
    "6200000000000005",
    "4242424242424242",
    "4000056655665556",
}

_DOC_HOSTS = {"example.com", "example.org", "example.net", "test.com", "localhost", "email.com"}


def luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def valid_card(number: str) -> bool:
    digits = re.sub(r"[^0-9]", "", number)
    return 13 <= len(digits) <= 19 and luhn(digits)


def is_test_card(number: str) -> bool:
    return re.sub(r"[^0-9]", "", number) in TEST_CARDS


def valid_ssn(value: str) -> bool:
    """Reject SSNs the SSA never issues (area 000/666/9xx, group 00, serial 0000)."""
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in {"000", "666"} or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    # 078-05-1120 is the famous wallet-card SSN; still a real format, keep it.
    return True


def valid_iban(value: str) -> bool:
    s = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def valid_npi(value: str) -> bool:
    """US National Provider Identifier: Luhn over '80840' + first 9 digits."""
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) != 10:
        return False
    return luhn("80840" + digits[:9] + digits[9])


def valid_nhs(value: str) -> bool:
    """UK NHS number: modulus-11 with weights 10..2."""
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) != 10:
        return False
    total = sum(int(d) * (10 - i) for i, d in enumerate(digits[:9]))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == int(digits[9])


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_secret(value: str, min_len: int = 20, min_entropy: float = 3.6) -> bool:
    """High-entropy opaque string heuristic for credentials without a known prefix."""
    if len(value) < min_len:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-\.]+", value):
        return False
    # Reject things that are clearly structured English or paths.
    if re.fullmatch(r"[a-z]+([_\-][a-z]+)*", value):
        return False
    charset_classes = sum(
        bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+/=_\-]")
    )
    return charset_classes >= 3 and shannon_entropy(value) >= min_entropy


def is_documentation_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1].lower()
    return domain in _DOC_HOSTS or domain.endswith(".example") or domain.endswith(".invalid")


def is_reserved_phone(value: str) -> bool:
    """NANP 555-0100..555-0199 is reserved for fiction."""
    digits = re.sub(r"[^0-9]", "", value)
    return "55501" in digits[-7:]
