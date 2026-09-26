"""Local policy checks before launching any network command."""

import pytest

from forgesec_agent.scanning.policy import require_approved

POLICY = [
    {
        "cidr": "192.168.10.0/24",
        "exclusions": ["192.168.10.1/32"],
        "scan_profiles": ["inventory", "standard"],
    }
]


def test_approved_host_and_profile() -> None:
    require_approved(POLICY, ["192.168.10.22"], "inventory")


@pytest.mark.parametrize(
    ("targets", "profile"),
    [
        (["192.168.11.1"], "inventory"),
        (["192.168.10.1"], "inventory"),
        (["192.168.10.22"], "full_tcp"),
        (["192.168.10.0/24"], None),
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
