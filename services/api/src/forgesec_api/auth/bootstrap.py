"""Create the first administrator without putting a password in shell history."""

from __future__ import annotations

import getpass

from forgesec_api.auth.service import AuthService
from forgesec_api.customer_binding import bind_customer
from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore


def main() -> None:
    settings = Settings.from_env()
    if settings.database_url:
        from forgesec_api.postgres_storage import PostgresStore

        store = PostgresStore(settings.runtime_data_dir, settings.database_url)
    else:
        store = JsonStore(settings.runtime_data_dir)
    store.initialize()
    try:
        bind_customer(
            store,
            settings.customer_id,
            adopt_legacy_data=settings.adopt_legacy_customer_data,
            required=settings.environment == "production",
        )
        auth = AuthService(store, settings.session_ttl_seconds)
        if auth.users():
            raise SystemExit(
                "Users already exist. Bootstrap is only for the first admin."
            )
        email = input("Administrator email: ").strip()
        password = getpass.getpass("Password (12+ characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise SystemExit("Passwords did not match")
        with store.locked():
            if auth.users():
                raise SystemExit("An administrator was created by another process.")
            user = auth.create_user(email, password, "admin")
        print(f"Administrator created: {user['email']}")
    finally:
        if settings.database_url:
            store.close()


if __name__ == "__main__":
    main()
