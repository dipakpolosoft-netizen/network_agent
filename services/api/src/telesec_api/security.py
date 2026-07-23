"""Token generation and one-way credential hashing."""

from __future__ import annotations

import hashlib
import secrets


def generate_enrollment_token() -> str:
    return f"tes_enr_{secrets.token_urlsafe(32)}"


def generate_agent_credential() -> str:
    return f"tes_agent_{secrets.token_urlsafe(48)}"


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()
