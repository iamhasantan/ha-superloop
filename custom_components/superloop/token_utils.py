"""Small authentication helpers that do not depend on Home Assistant."""

import base64
import binascii
import json


def strip_bearer_prefix(value: str) -> str:
    """Accept pasted raw tokens or Authorization: Bearer values."""
    value = value.strip()
    if value[:7].lower() == "bearer ":
        return value[7:].strip()
    return value


def jwt_expiry_ms(token: str) -> int | None:
    """Read optional expiry from a JWT without interpreting it as verified.

    The server validates the token; decoding is only used to avoid saving
    obviously expired tokens and to schedule reauthentication.
    """
    try:
        pieces = token.split(".")
        if len(pieces) != 3:
            return None
        payload = pieces[1] + "=" * (-len(pieces[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            return None
        if exp <= 0:
            return None
        return int(exp * 1000)
    except (ValueError, UnicodeError, TypeError, KeyError, IndexError, binascii.Error):
        return None
