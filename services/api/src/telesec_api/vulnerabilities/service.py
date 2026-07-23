"""Rate-conscious NVD CVE lookups for observed CPE service fingerprints."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from telesec_api.time import isoformat, utc_now

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class VulnerabilityError(RuntimeError):
    pass


class InvalidCpe(VulnerabilityError):
    pass


class VulnerabilityProviderUnavailable(VulnerabilityError):
    pass


def normalize_cpe(cpe: str) -> str:
    """Convert the CPE 2.2 URI emitted by Nmap into an NVD CPE 2.3 name."""
    value = cpe.strip()
    if value.startswith("cpe:2.3:"):
        components = value.split(":")
        if len(components) != 13:
            raise InvalidCpe("CPE 2.3 must contain 11 components")
        normalized = value
    elif value.startswith("cpe:/"):
        packed = value[5:].split(":")
        if not packed or len(packed) > 7:
            raise InvalidCpe("CPE 2.2 has an unsupported component count")
        packed.extend(["*"] * (7 - len(packed)))
        normalized = "cpe:2.3:" + ":".join([*packed, "*", "*", "*", "*"])
    else:
        raise InvalidCpe("Only CPE 2.2 URI or CPE 2.3 names are supported")

    components = normalized.split(":")
    if components[2] not in {"a", "h", "o"}:
        raise InvalidCpe("CPE part must be application, hardware, or operating system")
    if any(component in {"", "*", "-"} for component in components[3:6]):
        raise InvalidCpe("CPE vendor, product, and version are required")
    return normalized


class VulnerabilityService:
    def __init__(
        self,
        cache_dir: Path,
        *,
        api_key: str | None = None,
        cache_ttl_seconds: int = 86400,
        timeout_seconds: int = 20,
        opener: Callable[..., Any] = urlopen,
    ):
        self.cache_dir = cache_dir
        self.api_key = api_key
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.timeout_seconds = timeout_seconds
        self.opener = opener
        self._lock = threading.RLock()

    def lookup(self, cpe: str) -> dict[str, Any]:
        normalized = normalize_cpe(cpe)
        with self._lock:
            cached = self._read_cache(normalized)
            if cached is not None:
                cached["cached"] = True
                return cached
            result = self._request(cpe, normalized)
            self._write_cache(normalized, result)
            return result

    def _request(self, original_cpe: str, normalized_cpe: str) -> dict[str, Any]:
        query = urlencode(
            {
                "cpeName": normalized_cpe,
                "resultsPerPage": 2000,
            }
        )
        request = Request(
            f"{NVD_CVE_API}?{query}&isVulnerable&noRejected",
            headers={
                "Accept": "application/json",
                "User-Agent": "Telesec-Network-Agent/0.1 NVD-CVE-correlation",
                **({"apiKey": self.api_key} if self.api_key else {}),
            },
        )
        try:
            with self.opener(request, timeout=self.timeout_seconds) as response:
                payload = json.load(response)
        except HTTPError as exc:
            detail = "NVD request limit reached; retry later"
            if exc.code != 403 and exc.code != 429:
                detail = f"NVD returned HTTP {exc.code}"
            raise VulnerabilityProviderUnavailable(detail) from exc
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise VulnerabilityProviderUnavailable(
                "NVD could not be reached or returned an invalid response"
            ) from exc

        matches = [
            parsed
            for item in payload.get("vulnerabilities", [])
            if (parsed := _parse_vulnerability(item)) is not None
        ]
        matches.sort(
            key=lambda item: (
                not item["known_exploited"],
                -(item["cvss_score"] or -1),
                item["cve_id"],
            )
        )
        matches = matches[:500]
        return {
            "source": "NVD",
            "cpe": original_cpe,
            "normalized_cpe": normalized_cpe,
            "total": int(payload.get("totalResults", len(matches))),
            "returned": len(matches),
            "retrieved_at": isoformat(utc_now()),
            "cached": False,
            "vulnerabilities": matches,
            "notice": (
                "Potential matches based on the detected CPE, not confirmed "
                "exploitation. Verify the product version and vendor advisory "
                "before remediation."
            ),
        }

    def _cache_path(self, normalized_cpe: str) -> Path:
        digest = hashlib.sha256(normalized_cpe.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, normalized_cpe: str) -> dict[str, Any] | None:
        path = self._cache_path(normalized_cpe)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            retrieved_at = datetime.fromisoformat(payload["retrieved_at"])
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
            return None
        if retrieved_at.tzinfo is None:
            retrieved_at = retrieved_at.replace(tzinfo=UTC)
        if utc_now() - retrieved_at > self.cache_ttl:
            return None
        return payload

    def _write_cache(self, normalized_cpe: str, payload: dict[str, Any]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_path(normalized_cpe)
        temporary = path.with_suffix(f".{os.getpid()}.tmp")
        try:
            temporary.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def _parse_vulnerability(item: dict[str, Any]) -> dict[str, Any] | None:
    cve = item.get("cve", {})
    cve_id = str(cve.get("id", "")).upper()
    if not CVE_ID.fullmatch(cve_id):
        return None
    score, severity, version, vector = _best_cvss(cve.get("metrics", {}))
    return {
        "cve_id": cve_id,
        "severity": severity,
        "cvss_score": score,
        "cvss_version": version,
        "vector": vector,
        "description": _english_description(cve.get("descriptions", [])),
        "published_at": cve.get("published"),
        "last_modified_at": cve.get("lastModified"),
        "known_exploited": bool(cve.get("cisaExploitAdd")),
        "required_action": cve.get("cisaRequiredAction"),
        "action_due": cve.get("cisaActionDue"),
        "references": _safe_references(cve.get("references", [])),
    }


def _best_cvss(
    metrics: dict[str, Any],
) -> tuple[float | None, str, str | None, str | None]:
    candidates: list[tuple[bool, float, str | None, str | None, str]] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            data = metric.get("cvssData", {})
            score = data.get("baseScore")
            if not isinstance(score, int | float):
                continue
            candidates.append(
                (
                    metric.get("type") == "Primary",
                    float(score),
                    str(data.get("version")) if data.get("version") else None,
                    data.get("vectorString"),
                    str(data.get("baseSeverity") or metric.get("baseSeverity") or ""),
                )
            )
    if not candidates:
        return None, "unknown", None, None
    primary = [candidate for candidate in candidates if candidate[0]] or candidates
    _, score, version, vector, reported_severity = max(
        primary, key=lambda item: item[1]
    )
    severity = reported_severity.lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = _severity_from_score(score)
    return score, severity, version, vector


def _severity_from_score(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en" and description.get("value"):
            return str(description["value"])[:4000]
    return "No English description is available from NVD."


def _safe_references(references: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for reference in references:
        url = str(reference.get("url", ""))
        if urlsplit(url).scheme not in {"http", "https"} or url in urls:
            continue
        urls.append(url)
        if len(urls) == 20:
            break
    return urls
