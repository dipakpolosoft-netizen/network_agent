from telesec_agent.scanning import nmap_runner


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
