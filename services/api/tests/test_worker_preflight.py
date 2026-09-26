"""Read-only worker host preflight behavior."""

from __future__ import annotations

from uuid import uuid4

from forgesec_api.workers import check_runtime


def test_nuclei_preflight_accepts_local_configuration(monkeypatch, tmp_path) -> None:
    binary = tmp_path / "nuclei"
    binary.write_bytes(b"test binary")
    monkeypatch.setenv("FORGESEC_API_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("FORGESEC_WORKER_ID", str(uuid4()))
    monkeypatch.setenv("FORGESEC_WORKER_CREDENTIAL", "test-credential")
    monkeypatch.setenv("FORGESEC_NUCLEI_BINARY", str(binary))
    assert check_runtime.local_issues("nuclei") == []


def test_preflight_rejects_missing_identity_and_engine(monkeypatch) -> None:
    for name in (
        "FORGESEC_API_URL",
        "FORGESEC_WORKER_ID",
        "FORGESEC_WORKER_CREDENTIAL",
        "FORGESEC_NUCLEI_BINARY",
    ):
        monkeypatch.delenv(name, raising=False)
    issues = check_runtime.local_issues("nuclei")
    assert any("FORGESEC_WORKER_CREDENTIAL" in issue for issue in issues)
    assert any("FORGESEC_NUCLEI_BINARY" in issue for issue in issues)


def test_preflight_rejects_insecure_remote_url(monkeypatch, tmp_path) -> None:
    binary = tmp_path / "nuclei"
    binary.write_bytes(b"test binary")
    monkeypatch.setenv("FORGESEC_API_URL", "http://worker.example.com")
    monkeypatch.setenv("FORGESEC_WORKER_ID", str(uuid4()))
    monkeypatch.setenv("FORGESEC_WORKER_CREDENTIAL", "test-credential")
    monkeypatch.setenv("FORGESEC_NUCLEI_BINARY", str(binary))
    assert any("API URL" in issue for issue in check_runtime.local_issues("nuclei"))


def test_api_health_request_does_not_send_worker_credential(monkeypatch) -> None:
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return (
                b'{"status":"ok","service":"forgesec-api",'
                b'"environment":"production"}'
            )

    class Opener:
        def open(self, request, *, timeout):
            seen["url"] = request.full_url
            seen["headers"] = request.headers
            seen["timeout"] = timeout
            return Response()

    monkeypatch.setattr(check_runtime, "build_opener", lambda *_args: Opener())
    assert check_runtime.api_health_issue("https://scan.example.com") is None
    assert seen["url"] == "https://scan.example.com/health"
    assert "Authorization" not in seen["headers"]
    assert seen["timeout"] == 8


def test_api_health_rejects_non_object_response(monkeypatch) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return b"[]"

    class Opener:
        def open(self, _request, *, timeout):
            return Response()

    monkeypatch.setattr(check_runtime, "build_opener", lambda *_args: Opener())
    assert check_runtime.api_health_issue("https://scan.example.com") is not None


def test_remote_worker_rejects_development_api(monkeypatch) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return (
                b'{"status":"ok","service":"forgesec-api",'
                b'"environment":"development"}'
            )

    class Opener:
        def open(self, _request, *, timeout):
            return Response()

    monkeypatch.setattr(check_runtime, "build_opener", lambda *_args: Opener())
    assert "production mode" in check_runtime.api_health_issue("https://scan.example.com")
    assert check_runtime.api_health_issue("http://127.0.0.1:8000") is None
