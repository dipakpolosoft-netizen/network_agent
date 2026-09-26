"""Password verification, bounded login attempts, and revocable sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import timedelta
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, parse_timestamp, utc_now

ITERATIONS = 600_000
SESSION_COOKIE = "forgesec_session"
SECURE_SESSION_COOKIE = "__Host-forgesec_session"
ROLES = {"admin", "operator", "viewer"}
DUMMY_HASH = "$".join(
    (
        "pbkdf2_sha256",
        str(ITERATIONS),
        base64.urlsafe_b64encode(b"forgesec-no-user").decode(),
        base64.urlsafe_b64encode(bytes(32)).decode(),
    )
)


class AuthError(ValueError):
    pass


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return "$".join(
        (
            "pbkdf2_sha256",
            str(ITERATIONS),
            base64.urlsafe_b64encode(salt).decode(),
            base64.urlsafe_b64encode(digest).decode(),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or int(rounds) < ITERATIONS:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), base64.urlsafe_b64decode(salt), int(rounds)
        )
        return hmac.compare_digest(actual, base64.urlsafe_b64decode(expected))
    except (ValueError, TypeError):
        return False


class AuthService:
    def __init__(self, store: JsonStore, session_ttl_seconds: int):
        self.store = store
        self.session_ttl_seconds = session_ttl_seconds

    @staticmethod
    def public(user: dict) -> dict:
        return {
            key: value
            for key, value in user.items()
            if key not in {"password_hash", "password_changed_at", "session_version"}
        }

    def users(self) -> list[dict]:
        return sorted(self.store.list("users"), key=lambda user: user["email"])

    def create_user(self, email: str, password: str, role: str) -> dict:
        normalized = email.strip().casefold()
        if (
            "@" not in normalized
            or normalized.startswith("@")
            or normalized.endswith("@")
        ):
            raise AuthError("Enter a valid email address")
        if len(password) < 12 or len(password) > 256:
            raise AuthError("Password must contain 12 to 256 characters")
        if role not in ROLES:
            raise AuthError("Invalid role")
        with self.store.locked():
            if any(user["email"] == normalized for user in self.users()):
                raise AuthError("This email already has access")
            user = {
                "user_id": str(uuid4()),
                "email": normalized,
                "password_hash": password_hash(password),
                "role": role,
                "active": True,
                "created_at": isoformat(utc_now()),
                "password_changed_at": None,
                "session_version": 0,
            }
            self.store.write("users", user["user_id"], user)
            record_activity(
                self.store,
                event_type="user.created",
                message=f"User {normalized} created",
                resource_type="user",
                resource_id=user["user_id"],
                details={"role": role},
            )
            return self.public(user)

    def login(self, email: str, password: str) -> tuple[dict, str, str]:
        normalized = email.strip().casefold()
        attempt_key = hashlib.sha256(normalized.encode()).hexdigest()
        with self.store.locked():
            attempt = self.store.read("auth-attempts", attempt_key)
            now = utc_now()
            if attempt and parse_timestamp(attempt["until"]) <= now:
                self.store.delete("auth-attempts", attempt_key)
                attempt = None
            if attempt and attempt["count"] >= 5:
                raise AuthError("Too many attempts. Try again in 15 minutes")
            user = next(
                (item for item in self.users() if item["email"] == normalized), None
            )
            password_matches = verify_password(
                password, user["password_hash"] if user else DUMMY_HASH
            )
            valid = bool(user and user["active"] and password_matches)
            if not valid:
                self.store.write(
                    "auth-attempts",
                    attempt_key,
                    {
                        "count": (attempt["count"] if attempt else 0) + 1,
                        "until": attempt["until"]
                        if attempt
                        else isoformat(now + timedelta(minutes=15)),
                    },
                )
                raise AuthError("Invalid email or password")
            self.store.delete("auth-attempts", attempt_key)
            token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            self.store.write(
                "sessions",
                token_hash,
                {
                    "user_id": user["user_id"],
                    "csrf_token": csrf_token,
                    "password_changed_at": user.get("password_changed_at"),
                    "session_version": user.get("session_version", 0),
                    "created_at": isoformat(now),
                    "expires_at": isoformat(
                        now + timedelta(seconds=self.session_ttl_seconds)
                    ),
                },
            )
            record_activity(
                self.store,
                event_type="user.login",
                message=f"User {normalized} signed in",
                actor_type="user",
                actor_id=user["user_id"],
            )
            return self.public(user), token, csrf_token

    def session(self, token: str | None) -> tuple[dict, dict] | None:
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session = self.store.read("sessions", token_hash)
        if not session:
            return None
        if parse_timestamp(session["expires_at"]) <= utc_now():
            self.store.delete("sessions", token_hash)
            return None
        user = self.store.read("users", session["user_id"])
        if not user or not user["active"]:
            return None
        if session.get("password_changed_at") != user.get("password_changed_at"):
            return None
        if session.get("session_version", 0) != user.get("session_version", 0):
            return None
        return self.public(user), session

    def revoke(self, token: str | None) -> None:
        if token:
            self.store.delete("sessions", hashlib.sha256(token.encode()).hexdigest())

    def change_password(self, user_id: str, current: str, replacement: str) -> None:
        if len(replacement) < 12 or len(replacement) > 256:
            raise AuthError("New password must contain 12 to 256 characters")
        with self.store.locked():
            user = self.store.read("users", user_id)
            if not user or not verify_password(current, user["password_hash"]):
                raise AuthError("Current password is incorrect")
            user["password_hash"] = password_hash(replacement)
            user["password_changed_at"] = isoformat(utc_now())
            self.store.write("users", user_id, user)
            record_activity(
                self.store,
                event_type="user.password_changed",
                message="Operator password changed",
                actor_type="user",
                actor_id=user_id,
            )

    def set_active(self, user_id: str, active: bool) -> dict:
        with self.store.locked():
            user = self.store.read("users", user_id)
            if not user:
                raise AuthError("User not found")
            if not active and user["role"] == "admin":
                admins = [
                    item
                    for item in self.users()
                    if item["role"] == "admin" and item["active"]
                ]
                if len(admins) <= 1:
                    raise AuthError("The last active administrator cannot be disabled")
            user["active"] = active
            user["session_version"] = user.get("session_version", 0) + 1
            self.store.write("users", user_id, user)
            return self.public(user)
