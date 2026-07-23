from pathlib import Path

from telesec_agent.diagnostics import _is_file


def test_permission_denied_status_file_check_is_treated_as_missing(monkeypatch):
    def deny(_path):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "is_file", deny)

    protected_bootstrap = Path(
        "C:/ProgramData/Telesec/NetworkAgent/config/bootstrap.json"
    )

    assert _is_file(protected_bootstrap) is False
