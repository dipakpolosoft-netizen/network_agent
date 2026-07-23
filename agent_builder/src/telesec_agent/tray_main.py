"""Windowless entry point for the Telesec tray companion."""

from __future__ import annotations

import sys

from telesec_agent.tray import TrayApplication, stop_running_tray


def main() -> int:
    if "--stop" in sys.argv[1:]:
        stop_running_tray()
        return 0
    return TrayApplication().run()


if __name__ == "__main__":
    raise SystemExit(main())
