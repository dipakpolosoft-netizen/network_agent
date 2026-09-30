"""Recover a local development administrator without exposing the password."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import socket

from forgesec_api.activity import record_activity
from forgesec_api.auth.service import AuthError, AuthService, password_hash
from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now


def require_local_development(settings: Settings) -> None:
    if (
        settings.environment != "development"
        or settings.database_url
        or settings.api_host not in {"127.0.0.1", "localhost", "::1"}
    ):
        raise AuthError("Recovery is limited to the local development JSON store")


def recover_admin_password(store: JsonStore, email: str, replacement: str) -> None:
    normalized = email.strip().casefold()
    if not 12 <= len(replacement) <= 256:
        raise AuthError("Password must contain 12 to 256 characters")
    with store.locked():
        user = next(
            (item for item in store.list("users") if item["email"] == normalized),
            None,
        )
        if not user or user["role"] != "admin" or not user["active"]:
            raise AuthError("Active administrator not found in this local store")
        user["password_hash"] = password_hash(replacement)
        user["password_changed_at"] = isoformat(utc_now())
        user["session_version"] = user.get("session_version", 0) + 1
        store.write("users", user["user_id"], user)
        store.delete("auth-attempts", hashlib.sha256(normalized.encode()).hexdigest())
        record_activity(
            store,
            event_type="user.password_recovered",
            message=f"Local administrator password recovered for {normalized}",
            resource_type="user",
            resource_id=user["user_id"],
            severity="warning",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="Existing administrator email")
    args = parser.parse_args()
    settings = Settings.from_env()
    try:
        require_local_development(settings)
        if not settings.runtime_data_dir.is_dir():
            raise AuthError("Local runtime store does not exist")
        try:
            with socket.create_connection((settings.api_host, settings.api_port), 0.5):
                raise AuthError("Stop the local API before recovering its JSON store")
        except OSError:
            pass
        store = JsonStore(settings.runtime_data_dir)
        email = args.email.strip().casefold()
        if not any(
            user["email"] == email and user["role"] == "admin" and user["active"]
            for user in AuthService(store, settings.session_ttl_seconds).users()
        ):
            raise AuthError("Active administrator not found in this local store")
        print(f"Local store: {settings.runtime_data_dir}")
        if input(f"Type RESET {email} to continue: ").strip() != f"RESET {email}":
            raise AuthError("Recovery cancelled")
        replacement = getpass.getpass("New password (12+ characters): ")
        confirmation = getpass.getpass("Confirm new password: ")
        if replacement != confirmation:
            raise AuthError("Passwords did not match")
        recover_admin_password(store, email, replacement)
        print("Administrator password updated. Restart the API and sign in again.")
    except AuthError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
