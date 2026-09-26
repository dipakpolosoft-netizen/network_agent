"""Agent file and console logging."""

from __future__ import annotations

import logging
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _file_handler(path: Path) -> RotatingFileHandler:
    path.parent.mkdir(parents=True, exist_ok=True)
    return RotatingFileHandler(
        path,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )


def configure_logging(log_path: Path, *, console: bool) -> None:
    handlers: list[logging.Handler] = []
    fallback = (
        Path(tempfile.gettempdir()) / "ForgeSec" / "NetworkAgent" / "agent.log"
    )
    for candidate in dict.fromkeys((log_path, fallback)):
        try:
            handlers.append(_file_handler(candidate))
            break
        except OSError:
            continue
    if console:
        handlers.append(logging.StreamHandler())
    if not handlers:
        handlers.append(logging.NullHandler())
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
        force=True,
    )
