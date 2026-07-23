import logging
from pathlib import Path

from telesec_agent import logging_setup


def test_logging_uses_system_temp_when_agent_log_is_not_writable(
    monkeypatch, tmp_path
):
    attempts: list[Path] = []

    class FakeHandler(logging.NullHandler):
        def __init__(self, path, **_kwargs):
            candidate = Path(path)
            attempts.append(candidate)
            if len(attempts) == 1:
                raise PermissionError("protected")
            super().__init__()

    fallback_root = tmp_path / "system-temp"
    monkeypatch.setattr(logging_setup, "RotatingFileHandler", FakeHandler)
    monkeypatch.setattr(logging_setup.tempfile, "gettempdir", lambda: fallback_root)

    logging_setup.configure_logging(tmp_path / "agent" / "agent.log", console=False)

    assert attempts == [
        tmp_path / "agent" / "agent.log",
        fallback_root / "Telesec" / "NetworkAgent" / "agent.log",
    ]
