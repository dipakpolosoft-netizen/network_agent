"""Native logged-in user companion for Windows tray status."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
import webbrowser
from contextlib import suppress
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from forgesec_agent import __version__
from forgesec_agent.config import AgentPaths, default_data_directory

SERVICE_NAME = "ForgeSecNetworkAgent"
WINDOW_CLASS = "ForgeSecNetworkAgentTrayWindow"
WINDOW_TITLE = "ForgeSec Network Agent Tray"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
Tone = Literal["online", "attention", "offline"]

WM_TRAY = 0x0400 + 20
TIMER_ID = 1
TRAY_ICON_ID = 1
REFRESH_MS = 5000
CMD_OPEN = 1001
CMD_REFRESH = 1002
CMD_EXIT = 1003
CMD_START_SERVICE = 1004
CMD_STOP_SERVICE = 1005
CMD_RESTART_SERVICE = 1006
CMD_VIEW_LOG = 1007
CMD_OPEN_LOG_FOLDER = 1008
CMD_DIAGNOSTICS = 1009
CMD_ABOUT = 1010


@dataclass(frozen=True, slots=True)
class TraySnapshot:
    tone: Tone
    label: str
    service: str
    last_heartbeat: str
    nmap: str
    npcap: str
    activity: str | None
    dashboard_url: str | None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC)


def _time_label(value: datetime | None, now: datetime) -> str:
    if value is None:
        return "Never"
    seconds = max(0, int((now - value).total_seconds()))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


def query_service_running() -> bool:
    try:
        result = subprocess.run(
            ["sc.exe", "query", SERVICE_NAME],
            capture_output=True,
            check=False,
            creationflags=NO_WINDOW,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and "RUNNING" in result.stdout


def read_public_status(path: Path) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return document if isinstance(document, dict) else {}


def collect_snapshot(
    status_path: Path,
    *,
    service_running: bool | None = None,
    now: datetime | None = None,
) -> TraySnapshot:
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    running = query_service_running() if service_running is None else service_running
    document = read_public_status(status_path)
    last_heartbeat = _parse_time(document.get("last_heartbeat_at"))
    try:
        heartbeat_interval = int(document.get("heartbeat_interval_seconds", 30))
    except (TypeError, ValueError):
        heartbeat_interval = 30
    heartbeat_interval = max(10, heartbeat_interval)
    stale_after = max(90, heartbeat_interval * 3)
    stale = (
        last_heartbeat is None
        or (current_time - last_heartbeat).total_seconds() >= stale_after
    )
    raw_status = str(document.get("status", "starting"))

    if not running:
        tone: Tone = "offline"
        label = "Offline"
        service = "Stopped"
    elif stale:
        tone = "offline" if document else "attention"
        label = "Disconnected" if document else "Starting"
        service = "Running"
    elif raw_status == "busy":
        tone = "attention"
        label = "Scanning"
        service = "Running"
    elif raw_status == "degraded":
        tone = "attention"
        label = "Attention required"
        service = "Running"
    else:
        tone = "online"
        label = "Online"
        service = "Running"

    dashboard_url = document.get("dashboard_url")
    npcap = str(document.get("npcap_status") or "Unknown")
    return TraySnapshot(
        tone=tone,
        label=label,
        service=service,
        last_heartbeat=_time_label(last_heartbeat, current_time),
        nmap=str(document.get("nmap_version") or "Unavailable"),
        npcap=npcap.replace("_", " ").title(),
        activity=(str(document["activity"]) if document.get("activity") else None),
        dashboard_url=str(dashboard_url) if dashboard_url else None,
    )


def _draw_line(
    pixels: list[list[tuple[int, int, int, int]]],
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    width: float = 1.5,
) -> None:
    x1, y1 = start
    x2, y2 = end
    length_squared = float((x2 - x1) ** 2 + (y2 - y1) ** 2)
    for y, row in enumerate(pixels):
        for x in range(len(row)):
            if length_squared == 0:
                distance_squared = float((x - x1) ** 2 + (y - y1) ** 2)
            else:
                position = max(
                    0.0,
                    min(
                        1.0,
                        ((x - x1) * (x2 - x1) + (y - y1) * (y2 - y1))
                        / length_squared,
                    ),
                )
                projected_x = x1 + position * (x2 - x1)
                projected_y = y1 + position * (y2 - y1)
                distance_squared = (x - projected_x) ** 2 + (y - projected_y) ** 2
            if distance_squared <= width**2:
                row[x] = (255, 255, 255, 255)


def status_icon_pixels(tone: Tone, size: int = 32) -> bytes:
    colors = {
        "online": (18, 168, 117, 255),
        "attention": (210, 148, 46, 255),
        "offline": (214, 83, 97, 255),
    }
    pixels = [[(0, 0, 0, 0) for _x in range(size)] for _y in range(size)]
    center = (size - 1) / 2
    radius = size * 0.44
    for y, row in enumerate(pixels):
        for x in range(size):
            if (x - center) ** 2 + (y - center) ** 2 <= radius**2:
                row[x] = colors[tone]

    shield = [(16, 5), (24, 8), (23, 20), (16, 26), (9, 20), (8, 8)]
    for start, end in zip(shield, shield[1:] + shield[:1], strict=True):
        _draw_line(pixels, start, end)
    if tone == "online":
        _draw_line(pixels, (11, 15), (15, 19), width=1.8)
        _draw_line(pixels, (15, 19), (21, 12), width=1.8)
    elif tone == "offline":
        _draw_line(pixels, (12, 12), (20, 20), width=1.8)
        _draw_line(pixels, (20, 12), (12, 20), width=1.8)
    else:
        _draw_line(pixels, (16, 11), (16, 17), width=1.8)
        _draw_line(pixels, (16, 21), (16, 21), width=1.8)

    output = bytearray()
    for row in pixels:
        for red, green, blue, alpha in row:
            output.extend((blue, green, red, alpha))
    return bytes(output)


class _BitmapInfoHeader(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class _BitmapInfo(ctypes.Structure):
    _fields_ = [("bmiHeader", _BitmapInfoHeader), ("bmiColors", wintypes.DWORD)]


class _IconInfo(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


def create_native_icon(tone: Tone, size: int = 32) -> int:
    branded_icon = load_branded_icon(size)
    if branded_icon:
        return branded_icon

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    user32.GetDC.argtypes = [wintypes.HWND]
    user32.GetDC.restype = wintypes.HDC
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    user32.ReleaseDC.restype = ctypes.c_int
    user32.CreateIconIndirect.argtypes = [ctypes.POINTER(_IconInfo)]
    user32.CreateIconIndirect.restype = wintypes.HICON
    gdi32.CreateDIBSection.argtypes = [
        wintypes.HDC,
        ctypes.POINTER(_BitmapInfo),
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    gdi32.CreateDIBSection.restype = wintypes.HBITMAP
    gdi32.CreateBitmap.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.c_void_p,
    ]
    gdi32.CreateBitmap.restype = wintypes.HBITMAP
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteObject.restype = wintypes.BOOL
    header = _BitmapInfoHeader(
        ctypes.sizeof(_BitmapInfoHeader),
        size,
        -size,
        1,
        32,
        0,
        size * size * 4,
        0,
        0,
        0,
        0,
    )
    bitmap_info = _BitmapInfo(header, 0)
    bits = ctypes.c_void_p()
    screen_dc = user32.GetDC(None)
    color_bitmap = None
    mask_bitmap = None
    try:
        color_bitmap = gdi32.CreateDIBSection(
            screen_dc,
            ctypes.byref(bitmap_info),
            0,
            ctypes.byref(bits),
            None,
            0,
        )
        mask_bitmap = gdi32.CreateBitmap(size, size, 1, 1, None)
        if not color_bitmap or not mask_bitmap or not bits.value:
            raise OSError("Unable to create the ForgeSec tray icon")
        ctypes.memmove(bits.value, status_icon_pixels(tone, size), size * size * 4)
        icon_info = _IconInfo(True, 0, 0, mask_bitmap, color_bitmap)
        icon = user32.CreateIconIndirect(ctypes.byref(icon_info))
    finally:
        if color_bitmap:
            gdi32.DeleteObject(color_bitmap)
        if mask_bitmap:
            gdi32.DeleteObject(mask_bitmap)
        if screen_dc:
            user32.ReleaseDC(None, screen_dc)
    if not icon:
        raise OSError("Unable to create the ForgeSec tray icon")
    return int(icon)


def _source_tree_icon() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "installer"
        / "assets"
        / "forgesec-agent.ico"
    )


def load_branded_icon(size: int = 32) -> int | None:
    """Load the ForgeSec application icon for the notification area."""
    with suppress(Exception):
        import win32gui

        if getattr(sys, "frozen", False):
            icon = win32gui.ExtractIcon(0, str(Path(sys.executable)), 0)
            if icon:
                return int(icon)

        icon_path = _source_tree_icon()
        if icon_path.is_file():
            image_icon = 1
            load_from_file = 0x10
            icon = win32gui.LoadImage(
                0,
                str(icon_path),
                image_icon,
                size,
                size,
                load_from_file,
            )
            if icon:
                return int(icon)
    return None


def start_refresh_timer(hwnd: int) -> None:
    user32 = ctypes.windll.user32
    user32.SetTimer.argtypes = [
        wintypes.HWND,
        ctypes.c_size_t,
        wintypes.UINT,
        ctypes.c_void_p,
    ]
    user32.SetTimer.restype = ctypes.c_size_t
    if not user32.SetTimer(hwnd, TIMER_ID, REFRESH_MS, None):
        raise OSError("Unable to start the ForgeSec tray refresh timer")


def stop_refresh_timer(hwnd: int) -> None:
    user32 = ctypes.windll.user32
    user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
    user32.KillTimer.restype = wintypes.BOOL
    user32.KillTimer(hwnd, TIMER_ID)


class TrayApplication:
    def __init__(self, paths: AgentPaths | None = None):
        self.paths = paths or AgentPaths(default_data_directory().resolve())
        self.snapshot = collect_snapshot(self.paths.public_status)
        self.hwnd = 0
        self.hicon = 0
        self._tray_added = False

    @staticmethod
    def _tooltip(snapshot: TraySnapshot) -> str:
        return f"ForgeSec Network Agent - {snapshot.label}"

    def _notify_data(self, flags: int) -> tuple:
        return (
            self.hwnd,
            TRAY_ICON_ID,
            flags,
            WM_TRAY,
            self.hicon,
            self._tooltip(self.snapshot)[:127],
        )

    def _add_tray_icon(self) -> None:
        import win32gui

        self.hicon = create_native_icon(self.snapshot.tone)
        flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
        start_refresh_timer(self.hwnd)
        try:
            win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, self._notify_data(flags))
        except win32gui.error:
            win32gui.DestroyIcon(self.hicon)
            self.hicon = 0
        else:
            self._tray_added = True

    def _replace_tray_icon(self, snapshot: TraySnapshot) -> None:
        import win32gui

        previous_icon = self.hicon
        self.snapshot = snapshot
        next_icon = create_native_icon(snapshot.tone)
        self.hicon = next_icon
        flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
        operation = win32gui.NIM_MODIFY if self._tray_added else win32gui.NIM_ADD
        try:
            win32gui.Shell_NotifyIcon(operation, self._notify_data(flags))
        except win32gui.error:
            win32gui.DestroyIcon(next_icon)
            self.hicon = previous_icon
            if operation == win32gui.NIM_ADD:
                self._tray_added = False
        else:
            self._tray_added = True
            if previous_icon:
                win32gui.DestroyIcon(previous_icon)

    def _show_menu(self) -> None:
        import win32con
        import win32gui

        menu = win32gui.CreatePopupMenu()
        disabled = win32con.MF_STRING | win32con.MF_GRAYED
        win32gui.AppendMenu(menu, disabled, 0, "ForgeSec Network Agent")
        win32gui.AppendMenu(menu, disabled, 0, f"Status: {self.snapshot.label}")
        win32gui.AppendMenu(menu, disabled, 0, f"Service: {self.snapshot.service}")
        if self.snapshot.activity:
            win32gui.AppendMenu(
                menu, disabled, 0, f"Activity: {self.snapshot.activity}"
            )
        win32gui.AppendMenu(
            menu,
            disabled,
            0,
            f"Heartbeat: {self.snapshot.last_heartbeat}",
        )
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, None)
        win32gui.AppendMenu(menu, disabled, 0, f"Nmap: {self.snapshot.nmap}")
        win32gui.AppendMenu(menu, disabled, 0, f"Npcap: {self.snapshot.npcap}")
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, None)
        open_flags = win32con.MF_STRING
        if not self.snapshot.dashboard_url:
            open_flags |= win32con.MF_GRAYED
        win32gui.AppendMenu(menu, open_flags, CMD_OPEN, "Open Dashboard")
        win32gui.AppendMenu(menu, win32con.MF_STRING, CMD_VIEW_LOG, "View Agent Log")
        win32gui.AppendMenu(
            menu,
            win32con.MF_STRING,
            CMD_OPEN_LOG_FOLDER,
            "Open Logs Folder",
        )
        win32gui.AppendMenu(
            menu, win32con.MF_STRING, CMD_DIAGNOSTICS, "Diagnostics"
        )
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, None)
        if self.snapshot.service == "Stopped":
            win32gui.AppendMenu(
                menu,
                win32con.MF_STRING,
                CMD_START_SERVICE,
                "Start Service",
            )
        else:
            win32gui.AppendMenu(
                menu,
                win32con.MF_STRING,
                CMD_RESTART_SERVICE,
                "Restart Service",
            )
            win32gui.AppendMenu(
                menu,
                win32con.MF_STRING,
                CMD_STOP_SERVICE,
                "Stop Service",
            )
        win32gui.AppendMenu(menu, win32con.MF_STRING, CMD_REFRESH, "Refresh")
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, None)
        win32gui.AppendMenu(menu, win32con.MF_STRING, CMD_ABOUT, "About ForgeSec")
        win32gui.AppendMenu(menu, win32con.MF_STRING, CMD_EXIT, "Quit Status App")
        win32gui.SetMenuDefaultItem(menu, CMD_OPEN, 0)
        position = win32gui.GetCursorPos()
        win32gui.SetForegroundWindow(self.hwnd)
        win32gui.TrackPopupMenu(
            menu,
            (
                win32con.TPM_LEFTALIGN
                | win32con.TPM_BOTTOMALIGN
                | win32con.TPM_RIGHTBUTTON
            ),
            position[0],
            position[1],
            0,
            self.hwnd,
            None,
        )
        win32gui.PostMessage(self.hwnd, win32con.WM_NULL, 0, 0)
        win32gui.DestroyMenu(menu)

    def _open_dashboard(self) -> None:
        if self.snapshot.dashboard_url:
            webbrowser.open(self.snapshot.dashboard_url)

    def _open_log(self) -> None:
        if self.paths.log.is_file():
            self._open_path(self.paths.log)
            return
        self._message("ForgeSec Agent Log", "No agent log has been written yet.")

    def _open_log_folder(self) -> None:
        self._open_path(self.paths.log.parent)

    @staticmethod
    def _open_path(path: Path) -> None:
        try:
            os.startfile(str(path))
        except OSError as exc:
            TrayApplication._message("ForgeSec Network Agent", str(exc))

    def _show_diagnostics(self) -> None:
        details = [
            f"Version: {__version__}",
            f"Connection: {self.snapshot.label}",
            f"Service: {self.snapshot.service}",
            f"Last heartbeat: {self.snapshot.last_heartbeat}",
            f"Nmap: {self.snapshot.nmap}",
            f"Npcap: {self.snapshot.npcap}",
        ]
        if self.snapshot.activity:
            details.append(f"Activity: {self.snapshot.activity}")
        details.append(f"Data: {self.paths.root}")
        self._message("ForgeSec Diagnostics", "\n".join(details))

    @staticmethod
    def _message(title: str, message: str, flags: int = 0x40) -> int:
        return int(ctypes.windll.user32.MessageBoxW(None, message, title, flags))

    def _service_action(self, action: str) -> None:
        if action in {"stop", "restart"} and self.snapshot.activity:
            confirmed = self._message(
                "ForgeSec Network Agent",
                f"{self.snapshot.activity} is active. Continue with {action}?",
                0x21,
            )
            if confirmed != 1:
                return
        if getattr(sys, "frozen", False):
            executable = Path(sys.executable).with_name("ForgeSecAgent.exe")
            parameters = f"service {action}"
        else:
            executable = Path(sys.executable)
            parameters = f'-m forgesec_agent.main service {action}'
        if not executable.is_file():
            self._message(
                "ForgeSec Network Agent",
                f"Agent executable was not found: {executable}",
            )
            return
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            str(executable),
            parameters,
            str(executable.parent),
            0,
        )
        if result <= 32:
            self._message(
                "ForgeSec Network Agent",
                "Windows did not start the requested service action.",
            )

    def _on_command(self, _hwnd, _message, wparam, _lparam):
        import win32api
        import win32gui

        command = win32api.LOWORD(wparam)
        if command == CMD_OPEN:
            self._open_dashboard()
        elif command == CMD_VIEW_LOG:
            self._open_log()
        elif command == CMD_OPEN_LOG_FOLDER:
            self._open_log_folder()
        elif command == CMD_DIAGNOSTICS:
            self._show_diagnostics()
        elif command == CMD_START_SERVICE:
            self._service_action("start")
        elif command == CMD_STOP_SERVICE:
            self._service_action("stop")
        elif command == CMD_RESTART_SERVICE:
            self._service_action("restart")
        elif command == CMD_REFRESH:
            self._replace_tray_icon(collect_snapshot(self.paths.public_status))
        elif command == CMD_ABOUT:
            self._message(
                "About ForgeSec",
                "ForgeSec Network Agent\n"
                f"Version {__version__}\n"
                f"Status: {self.snapshot.label}\n"
                f"Service: {self.snapshot.service}",
            )
        elif command == CMD_EXIT:
            win32gui.DestroyWindow(self.hwnd)
        return 0

    def _on_tray(self, _hwnd, _message, _wparam, lparam):
        import win32api
        import win32con

        event = win32api.LOWORD(lparam)
        if event == win32con.WM_LBUTTONDBLCLK:
            self._open_dashboard()
        elif event in {win32con.WM_RBUTTONUP, win32con.WM_CONTEXTMENU}:
            self._show_menu()
        return 0

    def _on_timer(self, _hwnd, _message, wparam, _lparam):
        if wparam == TIMER_ID:
            self._replace_tray_icon(collect_snapshot(self.paths.public_status))
        return 0

    def _on_taskbar_created(self, _hwnd, _message, _wparam, _lparam):
        self._tray_added = False
        self._replace_tray_icon(collect_snapshot(self.paths.public_status))
        return 0

    def _on_destroy(self, _hwnd, _message, _wparam, _lparam):
        import win32gui

        stop_refresh_timer(self.hwnd)
        if self._tray_added:
            with suppress(win32gui.error):
                win32gui.Shell_NotifyIcon(
                    win32gui.NIM_DELETE,
                    self._notify_data(0),
                )
        if self.hicon:
            win32gui.DestroyIcon(self.hicon)
            self.hicon = 0
        win32gui.PostQuitMessage(0)
        return 0

    def _on_close(self, _hwnd, _message, _wparam, _lparam):
        import win32gui

        win32gui.DestroyWindow(self.hwnd)
        return 0

    def run(self) -> int:
        import win32api
        import win32con
        import win32gui

        if win32gui.FindWindow(WINDOW_CLASS, WINDOW_TITLE):
            return 0
        taskbar_created = win32gui.RegisterWindowMessage("TaskbarCreated")
        message_map = {
            win32con.WM_CLOSE: self._on_close,
            win32con.WM_COMMAND: self._on_command,
            win32con.WM_DESTROY: self._on_destroy,
            win32con.WM_TIMER: self._on_timer,
            WM_TRAY: self._on_tray,
            taskbar_created: self._on_taskbar_created,
        }
        window_class = win32gui.WNDCLASS()
        window_class.hInstance = win32api.GetModuleHandle(None)
        window_class.lpszClassName = WINDOW_CLASS
        window_class.lpfnWndProc = message_map
        atom = win32gui.RegisterClass(window_class)
        self.hwnd = win32gui.CreateWindow(
            atom,
            WINDOW_TITLE,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            window_class.hInstance,
            None,
        )
        self._add_tray_icon()
        win32gui.PumpMessages()
        return 0


def stop_running_tray(timeout_seconds: float = 10) -> bool:
    import win32con
    import win32gui

    window = win32gui.FindWindow(WINDOW_CLASS, WINDOW_TITLE)
    if not window:
        return False
    win32gui.PostMessage(window, win32con.WM_CLOSE, 0, 0)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not win32gui.FindWindow(WINDOW_CLASS, WINDOW_TITLE):
            return True
        time.sleep(0.1)
    return not win32gui.FindWindow(WINDOW_CLASS, WINDOW_TITLE)
