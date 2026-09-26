"""Fail closed when a control plane points at another customer's data store."""

from __future__ import annotations

import re

from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now


def bind_customer(
    store: JsonStore,
    customer_id: str | None,
    *,
    adopt_legacy_data: bool = False,
    required: bool = False,
) -> None:
    if required and not customer_id:
        raise RuntimeError("Production requires FORGESEC_CUSTOMER_ID")
    if customer_id and not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", customer_id):
        raise RuntimeError("Invalid FORGESEC_CUSTOMER_ID")
    with store.locked():
        existing = store.read("deployment", "customer")
        if existing:
            if existing.get("customer_id") != customer_id:
                raise RuntimeError(
                    "Customer identity does not match this data store; startup refused"
                )
            return
        if not customer_id:
            return
        has_data = store.contains_data(exclude=("deployment",))
        if has_data and not adopt_legacy_data:
            raise RuntimeError(
                "Existing unbound data requires a backup and explicit "
                "FORGESEC_ADOPT_LEGACY_CUSTOMER_DATA=true for one startup"
            )
        store.write(
            "deployment",
            "customer",
            {
                "customer_id": customer_id,
                "bound_at": isoformat(utc_now()),
                "adopted_legacy_data": has_data,
            },
        )
