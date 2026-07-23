from telesec_agent.scanning import nmap_runner


class SuccessfulProcess:
    returncode = 0

    def communicate(self, timeout=None):
        return "<nmaprun />", ""


def test_nmap_lookup_prefers_path(monkeypatch):
    expected = "C:\\tools\\nmap.exe"
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _name: expected)

    assert nmap_runner.find_nmap_executable() == expected


def test_nmap_lookup_checks_program_files(monkeypatch, tmp_path):
    executable = tmp_path / "Nmap" / "nmap.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"MZ")
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _name: None)
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)

    assert nmap_runner.find_nmap_executable() == str(executable)


def test_standard_scan_uses_light_service_detection(monkeypatch):
    commands = []
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command) or SuccessfulProcess(),
    )

    nmap_runner.NmapRunner().scan_host(
        "192.168.1.10", "standard", cancel_requested=lambda: False
    )

    assert "--top-ports" in commands[0]
    assert "--version-light" in commands[0]
    assert "--version-all" not in commands[0]


def test_full_tcp_scan_uses_all_ports_and_full_service_detection(monkeypatch):
    commands = []
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command) or SuccessfulProcess(),
    )

    nmap_runner.NmapRunner().scan_host(
        "192.168.1.10", "full_tcp", cancel_requested=lambda: False
    )

    assert "-p-" in commands[0]
    assert "--version-all" in commands[0]
    assert "--version-light" not in commands[0]
