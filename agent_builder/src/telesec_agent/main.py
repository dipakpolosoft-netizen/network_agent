"""Telesec Network Agent executable entry point."""

from __future__ import annotations

import argparse
import signal
import threading

from telesec_agent import __version__
from telesec_agent.config import AgentPaths, default_data_directory
from telesec_agent.diagnostics import doctor, print_json
from telesec_agent.runtime import build_runtime
from telesec_agent.service import run_service_dispatcher, service_command
from telesec_agent.storage import AgentStorage


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="TelesecAgent")
    root.add_argument("--version", action="version", version=__version__)
    subcommands = root.add_subparsers(dest="command", required=True)
    subcommands.add_parser("doctor")
    subcommands.add_parser("status")
    subcommands.add_parser("run-console")
    subcommands.add_parser("service-run", help=argparse.SUPPRESS)
    service = subcommands.add_parser("service")
    service.add_argument("action", choices=["install", "start", "stop", "remove"])
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
    storage.initialize()
    print_json(storage.read_json(paths.state) or {"status": "not_started"})


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "doctor":
        print_json(doctor())
    elif arguments.command == "status":
        show_status()
    elif arguments.command == "run-console":
        run_console()
    elif arguments.command == "service-run":
        run_service_dispatcher()
    elif arguments.command == "service":
        service_command(arguments.action)


if __name__ == "__main__":
    main()
