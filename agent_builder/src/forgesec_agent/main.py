"""ForgeSec Network Agent executable entry point."""

from __future__ import annotations

import argparse
import signal
import threading

from forgesec_agent import __version__
from forgesec_agent.config import (
    AgentPaths,
    default_data_directory,
    write_bootstrap_config,
)
from forgesec_agent.diagnostics import doctor, print_json
from forgesec_agent.runtime import build_runtime
from forgesec_agent.service import run_service_dispatcher, service_command
from forgesec_agent.storage import AgentStorage


def _safe_read_status(storage: AgentStorage, path) -> dict | None:
    try:
        return storage.read_json(path)
    except (OSError, ValueError):
        return None


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="ForgeSecAgent")
    root.add_argument("--version", action="version", version=__version__)
    subcommands = root.add_subparsers(dest="command", required=True)
    subcommands.add_parser("doctor")
    subcommands.add_parser("status")
    subcommands.add_parser("run-console")
    subcommands.add_parser("service-run", help=argparse.SUPPRESS)
    bootstrap = subcommands.add_parser("bootstrap", help=argparse.SUPPRESS)
    bootstrap.add_argument("--server-url", required=True)
    bootstrap.add_argument("--enrollment-token", required=True)
    service = subcommands.add_parser("service")
    service.add_argument(
        "action", choices=["install", "start", "stop", "restart", "remove"]
    )
    return root


def run_console() -> None:
    stop_event = threading.Event()

    def stop(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    build_runtime(console=True, stop_event=stop_event).run()


def show_status() -> None:
    paths = AgentPaths(default_data_directory().resolve())
    storage = AgentStorage(paths)
    public_status = _safe_read_status(storage, paths.public_status)
    if public_status is not None:
        print_json(public_status)
        return
    private_status = _safe_read_status(storage, paths.state)
    print_json(private_status or {"status": "not_started"})


def write_bootstrap(server_url: str, enrollment_token: str) -> None:
    paths = AgentPaths(default_data_directory().resolve())
    write_bootstrap_config(
        paths.bootstrap,
        server_url=server_url,
        enrollment_token=enrollment_token,
    )
    print_json({"status": "bootstrap_written", "path": str(paths.bootstrap)})


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "doctor":
        print_json(doctor())
    elif arguments.command == "status":
        show_status()
    elif arguments.command == "run-console":
        run_console()
    elif arguments.command == "bootstrap":
        write_bootstrap(arguments.server_url, arguments.enrollment_token)
    elif arguments.command == "service-run":
        run_service_dispatcher()
    elif arguments.command == "service":
        service_command(arguments.action)


if __name__ == "__main__":
    main()
