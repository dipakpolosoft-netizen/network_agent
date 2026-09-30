from forgesec_agent.scanning import nmap_runner

DISCOVERY_XML = (
    '<?xml version="1.0"?>\n<nmaprun><host><status state="up"/>'
    '<address addr="192.168.1.1" addrtype="ipv4"/></host></nmaprun>\n'
)


class SuccessfulProcess:
    returncode = 0

    def communicate(self, timeout=None):
        return "<nmaprun />", ""


class HangingProcess:
    returncode = None

    def communicate(self, timeout=None):
        if timeout == 1:
            raise nmap_runner.subprocess.TimeoutExpired("nmap", timeout)
        return "", ""

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class DiscoveryProcess:
    def __init__(self, command):
        self.returncode = None
        self.xml_path = nmap_runner.Path(command[command.index("-oX") + 1])
        self.poll_count = 0

    def poll(self):
        self.poll_count += 1
        if self.poll_count >= 2:
            self.xml_path.write_text(DISCOVERY_XML, encoding="utf-8")
            self.returncode = 0
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def communicate(self, timeout=None):
        return None, None


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


def test_discovery_reports_progress_from_managed_process(monkeypatch):
    commands = []
    updates = []
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command)
        or DiscoveryProcess(command),
    )

    result = nmap_runner.NmapRunner().discover(
        "192.168.1.0/24", progress_callback=updates.append
    )

    assert result == DISCOVERY_XML
    assert "--stats-every" in commands[0]
    assert updates[-1].progress_percent == 100
    assert updates[-1].found_count == 1


def test_discovery_passes_exclusions_to_nmap(monkeypatch):
    commands = []
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command)
        or DiscoveryProcess(command),
    )
    nmap_runner.NmapRunner().discover(
        "192.168.1.0/24", exclusions=["192.168.1.11/32"]
    )
    assert commands[0][-3:] == ["--exclude", "192.168.1.11/32", "192.168.1.0/24"]


def test_discovery_can_stop_managed_process(monkeypatch):
    process = None

    def create_process(command, **_kwargs):
        nonlocal process
        process = DiscoveryProcess(command)
        return process

    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", create_process)

    try:
        nmap_runner.NmapRunner().discover(
            "192.168.1.0/24", cancel_requested=lambda: True
        )
    except nmap_runner.ScanCancelled:
        assert process is not None
        assert process.returncode == -15
    else:
        raise AssertionError("Expected discovery cancellation")


def test_discovery_timeout_keeps_complete_partial_host_records(monkeypatch):
    class TimedOutDiscoveryProcess(DiscoveryProcess):
        def __init__(self, command):
            super().__init__(command)
            self.xml_path.write_text(DISCOVERY_XML, encoding="utf-8")

        def poll(self):
            return self.returncode

    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: TimedOutDiscoveryProcess(command),
    )
    try:
        nmap_runner.NmapRunner(timeout_seconds=0).discover("192.168.1.0/24")
    except nmap_runner.ScanTimedOut as exc:
        assert exc.partial_xml is not None
        assert 'addr="192.168.1.1"' in exc.partial_xml
    else:
        raise AssertionError("Expected a partial discovery timeout")


def test_known_host_check_uses_bounded_discovery_probes(monkeypatch):
    commands = []
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command) or SuccessfulProcess(),
    )
    result = nmap_runner.NmapRunner().verify_known_host(
        "192.168.1.20", cancel_requested=lambda: False
    )
    assert result == "<nmaprun />"
    assert commands[0][-1] == "192.168.1.20"
    assert "-sn" in commands[0]
    assert "--disable-arp-ping" in commands[0]
    assert "-PS22,80,443" in commands[0]
    assert "-PA80,443" in commands[0]
    assert "-p-" not in commands[0]


def test_known_host_check_can_be_cancelled(monkeypatch):
    process = HangingProcess()
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(
        nmap_runner.subprocess, "Popen", lambda *_args, **_kwargs: process
    )
    try:
        nmap_runner.NmapRunner().verify_known_host(
            "192.168.1.20", cancel_requested=lambda: True
        )
    except nmap_runner.ScanCancelled:
        assert process.returncode == -15
    else:
        raise AssertionError("Expected known-host check cancellation")


def test_inventory_scan_uses_fast_common_port_detection(monkeypatch):
    commands = []
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command) or SuccessfulProcess(),
    )

    nmap_runner.NmapRunner().scan_host(
        "192.168.1.10", "inventory", cancel_requested=lambda: False
    )

    assert "--top-ports" in commands[0]
    assert "200" in commands[0]
    assert "--max-retries" in commands[0]
    assert "--version-light" in commands[0]
    assert "--version-all" not in commands[0]
    assert "-sT" in commands[0]
    assert "-sU" not in commands[0]
    assert commands[0][commands[0].index("--host-timeout") + 1] == "480s"


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
    assert "1000" in commands[0]
    assert "--version-light" in commands[0]
    assert "--version-all" not in commands[0]
    assert "-sU" not in commands[0]
    assert commands[0][commands[0].index("--host-timeout") + 1] == "900s"


def test_network_services_scan_uses_bounded_tcp_udp_ports(monkeypatch):
    commands = []
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner, "_is_windows_admin", lambda: True)
    monkeypatch.setattr(
        nmap_runner.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command) or SuccessfulProcess(),
    )

    nmap_runner.NmapRunner().scan_host(
        "192.168.1.10", "network_services", cancel_requested=lambda: False
    )

    assert "-sU" in commands[0]
    assert "-sS" in commands[0]
    assert nmap_runner.NETWORK_SERVICE_PORTS in commands[0]
    assert "-O" not in commands[0]
    assert commands[0][commands[0].index("--host-timeout") + 1] == "720s"


def test_network_services_requires_elevated_probe(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner, "_is_windows_admin", lambda: False)
    try:
        nmap_runner.NmapRunner().scan_host(
            "192.168.1.10", "network_services", cancel_requested=lambda: False
        )
    except nmap_runner.NmapExecutionError as exc:
        assert "elevated probe" in str(exc)
    else:
        raise AssertionError("Expected a clear UDP privilege error")


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
    assert "-sU" not in commands[0]
    assert commands[0][commands[0].index("--host-timeout") + 1] == "2700s"


def test_long_host_scan_cancel_terminates_nmap(monkeypatch):
    process = HangingProcess()
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(
        nmap_runner.subprocess, "Popen", lambda *_args, **_kwargs: process
    )
    try:
        nmap_runner.NmapRunner().scan_host(
            "192.168.1.10", "full_tcp", cancel_requested=lambda: True
        )
    except nmap_runner.ScanCancelled:
        assert process.returncode == -15
    else:
        raise AssertionError("Expected Nmap to stop after cancellation")


def test_control_connection_failure_terminates_nmap(monkeypatch):
    process = HangingProcess()
    monkeypatch.setattr(nmap_runner, "find_nmap_executable", lambda: "nmap.exe")
    monkeypatch.setattr(nmap_runner, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(
        nmap_runner.subprocess, "Popen", lambda *_args, **_kwargs: process
    )

    def unavailable_control():
        raise OSError("Control connection lost")

    try:
        nmap_runner.NmapRunner().scan_host(
            "192.168.1.10", "full_tcp", cancel_requested=unavailable_control
        )
    except OSError as exc:
        assert "Control connection lost" in str(exc)
        assert process.returncode == -15
    else:
        raise AssertionError("Expected control failure to stop Nmap")
