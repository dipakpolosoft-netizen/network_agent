from pathlib import Path

import pytest

from telesec_agent import service


@pytest.mark.parametrize(
    ("exists", "operation"),
    [(False, "create"), (True, "config")],
)
def test_service_install_is_upgrade_safe(monkeypatch, exists, operation):
    calls = []
    monkeypatch.setattr(service.sys, "frozen", True, raising=False)
    monkeypatch.setattr(service.sys, "executable", str(Path("TelesecAgent.exe")))
    monkeypatch.setattr(service, "_service_exists", lambda: exists)
    monkeypatch.setattr(service, "_run_sc", lambda *args: calls.append(args))

    service.service_command("install")

    assert calls[0][0] == operation
    assert calls[0][1] == service.SERVICE_NAME
    assert calls[1][0] == "description"
    assert calls[2][0] == "failure"


def test_source_checkout_cannot_register_service(monkeypatch):
    monkeypatch.delattr(service.sys, "frozen", raising=False)

    with pytest.raises(RuntimeError, match="packaged agent executable"):
        service.service_command("install")


def test_service_stop_waits_until_windows_reports_stopped(monkeypatch):
    calls = []
    waits = []
    monkeypatch.setattr(service, "_service_state", lambda: "RUNNING")
    monkeypatch.setattr(service, "_run_sc", lambda *args: calls.append(args))
    monkeypatch.setattr(
        service,
        "_wait_for_service_state",
        lambda expected: waits.append(expected),
    )

    service.service_command("stop")

    assert calls == [("stop", service.SERVICE_NAME)]
    assert waits == ["STOPPED"]


def test_service_remove_stops_service_before_deletion(monkeypatch):
    calls = []
    waits = []
    monkeypatch.setattr(service, "_service_state", lambda: "RUNNING")
    monkeypatch.setattr(service, "_run_sc", lambda *args: calls.append(args))
    monkeypatch.setattr(
        service,
        "_wait_for_service_state",
        lambda expected: waits.append(expected),
    )

    service.service_command("remove")

    assert calls == [
        ("stop", service.SERVICE_NAME),
        ("delete", service.SERVICE_NAME),
    ]
    assert waits == ["STOPPED", None]
