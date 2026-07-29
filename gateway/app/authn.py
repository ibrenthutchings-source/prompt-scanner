"""HTTP Basic Auth for the CISO-facing dashboard surfaces.

Separate from the `X-API-Key` gate in `main.py`: that one is a machine
shared secret for the proxy/extension, this is a human login, challenged
via the browser's native Basic Auth prompt.
"""

from __future__ import annotations

import base64
import binascii
import secrets

from app.config import Settings


def basic_auth_ok(header: str | None, settings: Settings) -> bool:
    if not settings.dashboard_password:
        return True
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:]).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    username, _, password = decoded.partition(":")
    return secrets.compare_digest(username, settings.dashboard_username) and secrets.compare_digest(
        password, settings.dashboard_password
    )
