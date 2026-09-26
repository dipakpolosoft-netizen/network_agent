"""Read-only source freeze checks for a ForgeSec release candidate."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCKS = (
    "services/api/requirements.lock",
    "agent_builder/requirements.lock",
)
LOCK_PACKAGES = {
    "services/api/requirements.lock": {"fastapi", "hatchling", "psycopg", "uvicorn"},
    "agent_builder/requirements.lock": {"hatchling", "psutil", "pyinstaller", "pywin32", "pytest", "ruff"},
}
CONTAINER_FILES = (
    "services/api/Dockerfile",
    "apps/web/Dockerfile",
    "docker-compose.yml",
    "docker-compose.production.yml",
)
SENSITIVE_PATH = re.compile(
    r"(^|/)(\.env(\..*)?|[^/]+\.(pem|pfx|p12|key)|nmap-oem\.exe)$",
    re.IGNORECASE,
)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def version_issues(root: Path) -> tuple[str | None, list[str]]:
    issues: list[str] = []
    try:
        api = tomllib.loads((root / "services/api/pyproject.toml").read_text(encoding="utf-8"))
        agent = tomllib.loads((root / "agent_builder/pyproject.toml").read_text(encoding="utf-8"))
        web = json.loads((root / "apps/web/package.json").read_text(encoding="utf-8"))
        lock = json.loads((root / "apps/web/package-lock.json").read_text(encoding="utf-8"))
        tree = ast.parse((root / "agent_builder/src/forgesec_agent/__init__.py").read_text(encoding="utf-8"))
        agent_source = next(
            ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
        )
    except (OSError, ValueError, SyntaxError, StopIteration, KeyError, TypeError) as exc:
        return None, [f"Cannot read release version metadata: {exc}"]

    try:
        versions = {
            "API": api["project"]["version"],
            "agent package": agent["project"]["version"],
            "agent source": agent_source,
            "web package": web["version"],
            "web lock": lock["version"],
            "web lock root": lock["packages"][""]["version"],
        }
    except (KeyError, TypeError) as exc:
        return None, [f"Release version metadata is incomplete: {exc}"]
    version = str(versions["agent package"])
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        issues.append("Release version must be MAJOR.MINOR.PATCH")
    for label, value in versions.items():
        if value != version:
            issues.append(f"{label} version {value} differs from {version}")
    root_package = lock["packages"][""]
    for section in ("dependencies", "devDependencies"):
        if root_package.get(section, {}) != web.get(section, {}):
            issues.append(f"Web package-lock root {section} differs from package.json")
    return version, issues


def sensitive_tracked_paths(paths: list[str]) -> list[str]:
    blocked: list[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        if normalized == ".env.example":
            continue
        if SENSITIVE_PATH.search(normalized) or normalized.startswith(
            ("services/api/runtime-data/", "agent_builder/installer/dependencies/")
        ):
            if not normalized.endswith("/.gitkeep") and not normalized.endswith("/README.md"):
                blocked.append(path)
    return blocked


def lock_issues(root: Path, name: str) -> list[str]:
    path = root / name
    if not path.is_file():
        return [f"Python production dependency lock is missing: {name}"]
    contents = path.read_text(encoding="utf-8")
    blocks = re.findall(
        r"(?ms)^([a-zA-Z0-9_.-]+)==([^\s\\]+)\s*\\\n(.*?)(?=^[a-zA-Z0-9_.-]+==|\Z)",
        contents,
    )
    packages = {package.lower().replace("_", "-") for package, _, _ in blocks}
    issues = []
    if not blocks or len(packages) != len(blocks):
        issues.append(f"Python lock is empty, malformed, or duplicates a package: {name}")
    for package, _, body in blocks:
        if not re.search(r"--hash=sha256:[0-9a-f]{64}", body):
            issues.append(f"Python lock package lacks a SHA-256 hash: {name}: {package}")
    missing = LOCK_PACKAGES[name] - packages
    if missing:
        issues.append(f"Python lock lacks required packages: {name}: {', '.join(sorted(missing))}")
    return issues


def unpinned_container_images(root: Path) -> list[str]:
    images: list[str] = []
    seen: set[str] = set()
    for name in CONTAINER_FILES:
        path = root / name
        if not path.is_file():
            images.append(f"{name}: missing")
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            docker_from = re.match(r"\s*FROM\s+(\S+)", line, re.IGNORECASE)
            compose_image = re.match(r"\s*image:\s*(\S+)", line)
            match = docker_from or compose_image
            if not match:
                continue
            image = match.group(1)
            if not re.search(r"@sha256:[0-9a-fA-F]{64}$", image):
                label = f"{name}: {image}"
                if label not in seen:
                    images.append(label)
                    seen.add(label)
    return images


def inspect(root: Path) -> dict:
    commit = _git(root, "rev-parse", "HEAD").strip()
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=normal").splitlines()
    tracked = _git(root, "ls-files", "-z").split("\0")
    version, issues = version_issues(root)
    if status:
        issues.append(f"Working tree has {len(status)} changed or untracked entries; review and freeze it")
    for path in LOCKS:
        issues.extend(lock_issues(root, path))
    for path in sensitive_tracked_paths(tracked):
        issues.append(f"Potential secret or distributable is tracked: {path}")
    for image in unpinned_container_images(root):
        issues.append(f"Container image is not digest-pinned: {image}")
    return {
        "commit": commit,
        "version": version,
        "working_tree_entries": len(status),
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", help="Require this exact candidate commit SHA")
    args = parser.parse_args()
    try:
        result = inspect(ROOT)
    except RuntimeError as exc:
        print(f"NOT FROZEN: {exc}", file=sys.stderr)
        return 2
    if args.expected_commit and result["commit"].lower() != args.expected_commit.lower():
        result["issues"].append("HEAD differs from the expected release candidate commit")
    print(f"HEAD {result['commit']} / version {result['version']}")
    for issue in result["issues"]:
        print(f"NOT FROZEN: {issue}")
    if result["issues"]:
        return 1
    print("Source freeze checks passed. Run dependency advisories and build validation separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
