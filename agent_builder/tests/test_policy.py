"""Local policy checks before launching any network command."""

import pytest
from approved_policy import approved_policy

from forgesec_agent.scanning.policy import exclusions_for_scope, require_approved

POLICY = [
    approved_policy(
        "192.168.10.0/24",
        exclusions=["192.168.10.1/32"],
        scan_profiles=["inventory", "standard"],
    )
]


def test_approved_host_and_profile() -> None:
    require_approved(POLICY, ["192.168.10.22"], "inventory")
    require_approved(POLICY, ["192.168.10.0/24"])
    assert exclusions_for_scope(POLICY, "192.168.10.0/24") == ["192.168.10.1/32"]


@pytest.mark.parametrize(
    ("targets", "profile"),
    [
        (["192.168.11.1"], "inventory"),
        (["192.168.10.1"], "inventory"),
        (["192.168.10.22"], "full_tcp"),
        (["192.168.10.22", "192.168.11.1"], "standard"),
    ],
)
def test_rejects_out_of_policy_targets(targets: list[str], profile: str | None) -> None:
    with pytest.raises(ValueError):
        require_approved(POLICY, targets, profile)


@pytest.mark.parametrize("policy", [None, [], {}])
def test_missing_policy_fails_closed(policy: object) -> None:
    with pytest.raises(ValueError):
        require_approved(policy, ["192.168.10.22"])


@pytest.mark.parametrize(
    "override",
    [
        {"expires_on": "2000-01-01"},
        {"authorization_confirmed": False},
        {"approval_reference": ""},
    ],
)
def test_inactive_approval_fails_closed(override: dict) -> None:
    with pytest.raises(ValueError, match="approval"):
        require_approved(
            [approved_policy("192.168.10.0/24", **override)], ["192.168.10.22"]
        )


def test_legacy_policy_fails_closed() -> None:
    with pytest.raises(ValueError, match="approval"):
        require_approved([{"cidr": "192.168.10.0/24"}], ["192.168.10.22"])
