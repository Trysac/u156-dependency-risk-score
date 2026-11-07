"""Score dependency risk from offline facts: release staleness, maintainers, and licenses."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Literal

__all__ = [
    "DEFAULT_LICENSES",
    "Package",
    "RiskError",
    "RiskErrorCode",
    "RiskReport",
    "Vulnerability",
    "Weights",
    "__version__",
    "load_facts",
    "score_all",
    "score_package",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

RiskErrorCode = Literal["invalid_facts", "input_too_large", "invalid_date", "invalid_weights"]

# Explicit bundled SPDX table checked 2026-11-06
DEFAULT_LICENSES: Mapping[str, str] = {
    "MIT": "permissive",
    "Apache-2.0": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "ISC": "permissive",
    "0BSD": "permissive",
    "Zlib": "permissive",
    "Unlicense": "permissive",
    "PSF-2.0": "permissive",
    "LGPL-2.1-only": "weak_copyleft",
    "LGPL-2.1-or-later": "weak_copyleft",
    "LGPL-3.0-only": "weak_copyleft",
    "LGPL-3.0-or-later": "weak_copyleft",
    "MPL-2.0": "weak_copyleft",
    "EPL-2.0": "weak_copyleft",
    "GPL-2.0-only": "strong_copyleft",
    "GPL-2.0-or-later": "strong_copyleft",
    "GPL-3.0-only": "strong_copyleft",
    "GPL-3.0-or-later": "strong_copyleft",
    "AGPL-3.0-only": "strong_copyleft",
    "AGPL-3.0-or-later": "strong_copyleft",
}


class RiskError(ValueError):
    """Base error class with a machine-readable code."""

    def __init__(self, code: RiskErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: RiskErrorCode = code


@dataclass(frozen=True)
class Weights:
    """Weights configuration for scoring dependency risks."""

    critical: int = 40
    high: int = 25
    medium: int = 10
    low: int = 3
    vuln_cap: int = 60
    aging: int = 10
    stale: int = 20
    single_maintainer: int = 10
    deprecated: int = 25
    weak_copyleft: int = 10
    strong_copyleft: int = 20
    unknown_license: int = 15

    def __post_init__(self) -> None:
        for field_name in (
            "critical",
            "high",
            "medium",
            "low",
            "vuln_cap",
            "aging",
            "stale",
            "single_maintainer",
            "deprecated",
            "weak_copyleft",
            "strong_copyleft",
            "unknown_license",
        ):
            val = getattr(self, field_name)
            # bool is a subclass of int in Python, explicitly reject booleans
            if isinstance(val, bool) or not isinstance(val, int) or val < 0 or val > 100:
                raise RiskError(
                    "invalid_weights",
                    f"Field '{field_name}' must be an integer between 0 and 100",
                )


@dataclass(frozen=True)
class Vulnerability:
    """Vulnerability affecting a package version."""

    id: str
    severity: Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True)
class Package:
    """Offline facts known about a package."""

    name: str
    version: str
    last_release: date | None = None
    maintainers: int | None = None
    license: str | None = None
    deprecated: bool = False
    vulnerabilities: tuple[Vulnerability, ...] = ()


@dataclass(frozen=True)
class RiskReport:
    """Risk assessment result for a package."""

    name: str
    version: str
    score: int
    level: Literal["low", "medium", "high", "critical"]
    reasons: tuple[str, ...]


def _parse_iso_date(raw_date: str, json_path: str) -> date:
    """Parse an ISO date strictly from exactly 10 characters (YYYY-MM-DD)."""
    trimmed_raw = raw_date[:200]
    if len(raw_date) != 10 or raw_date[4] != "-" or raw_date[7] != "-":
        raise RiskError("invalid_date", f"Invalid date at {json_path}: {trimmed_raw}")
    try:
        return date.fromisoformat(raw_date)
    except ValueError as exc:
        raise RiskError("invalid_date", f"Invalid date at {json_path}: {trimmed_raw}") from exc


def load_facts(
    text: str,
    *,
    max_bytes: int = 5_242_880,
    max_packages: int = 10_000,
) -> list[Package]:
    """Parse and validate package facts from JSON text."""
    encoded_len = len(text.encode("utf-8"))
    if encoded_len > max_bytes:
        raise RiskError(
            "input_too_large",
            f"Input size {encoded_len} exceeds maximum allowed {max_bytes} bytes",
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RiskError("invalid_facts", f"Invalid JSON: {str(exc)[:200]}") from exc

    if not isinstance(data, dict):
        raise RiskError("invalid_facts", "Root of facts must be a JSON object")

    if "packages" not in data or not isinstance(data["packages"], list):
        raise RiskError("invalid_facts", "Expected 'packages' list at root")

    raw_pkgs = data["packages"]
    if len(raw_pkgs) > max_packages:
        raise RiskError(
            "input_too_large",
            f"Package count {len(raw_pkgs)} exceeds maximum allowed {max_packages}",
        )

    packages: list[Package] = []
    for idx, raw_pkg in enumerate(raw_pkgs):
        pkg_path = f"packages[{idx}]"
        if not isinstance(raw_pkg, dict):
            raise RiskError("invalid_facts", f"{pkg_path} must be an object")

        # name
        if "name" not in raw_pkg:
            raise RiskError("invalid_facts", f"{pkg_path}.name is required")
        name = raw_pkg["name"]
        if not isinstance(name, str) or not name.strip():
            raise RiskError("invalid_facts", f"{pkg_path}.name must be a non-empty string")

        # version
        if "version" not in raw_pkg:
            raise RiskError("invalid_facts", f"{pkg_path}.version is required")
        version = raw_pkg["version"]
        if not isinstance(version, str) or not version.strip():
            raise RiskError("invalid_facts", f"{pkg_path}.version must be a non-empty string")

        # last_release
        last_release_raw = raw_pkg.get("last_release")
        parsed_release: date | None = None
        if last_release_raw is not None:
            if not isinstance(last_release_raw, str):
                raise RiskError(
                    "invalid_facts", f"{pkg_path}.last_release must be a string or null"
                )
            parsed_release = _parse_iso_date(last_release_raw, f"{pkg_path}.last_release")

        # maintainers
        maintainers = raw_pkg.get("maintainers")
        if maintainers is not None and (
            isinstance(maintainers, bool) or not isinstance(maintainers, int) or maintainers < 0
        ):
            raise RiskError(
                "invalid_facts",
                f"{pkg_path}.maintainers must be an integer >= 0 or null",
            )

        # license
        license_id = raw_pkg.get("license")
        if license_id is not None and not isinstance(license_id, str):
            raise RiskError("invalid_facts", f"{pkg_path}.license must be a string or null")

        # deprecated
        deprecated = raw_pkg.get("deprecated", False)
        if not isinstance(deprecated, bool):
            raise RiskError("invalid_facts", f"{pkg_path}.deprecated must be a boolean")

        # vulnerabilities
        vulns_raw = raw_pkg.get("vulnerabilities", [])
        if not isinstance(vulns_raw, list):
            raise RiskError("invalid_facts", f"{pkg_path}.vulnerabilities must be a list")
        if len(vulns_raw) > 1_000:
            raise RiskError(
                "input_too_large",
                f"{pkg_path}.vulnerabilities exceeds maximum of 1000 items",
            )

        vulns: list[Vulnerability] = []
        for v_idx, v in enumerate(vulns_raw):
            v_path = f"{pkg_path}.vulnerabilities[{v_idx}]"
            if not isinstance(v, dict):
                raise RiskError("invalid_facts", f"{v_path} must be an object")
            v_id = v.get("id")
            if not isinstance(v_id, str) or not v_id.strip():
                raise RiskError("invalid_facts", f"{v_path}.id must be a non-empty string")
            severity = v.get("severity")
            if severity not in ("critical", "high", "medium", "low"):
                raise RiskError(
                    "invalid_facts",
                    f"{v_path}.severity must be one of 'critical', 'high', 'medium', 'low'",
                )
            vulns.append(Vulnerability(id=v_id, severity=severity))

        packages.append(
            Package(
                name=name,
                version=version,
                last_release=parsed_release,
                maintainers=maintainers,
                license=license_id,
                deprecated=deprecated,
                vulnerabilities=tuple(vulns),
            )
        )

    return packages


DEFAULT_WEIGHTS = Weights()


def score_package(
    pkg: Package,
    *,
    as_of: date,
    weights: Weights = DEFAULT_WEIGHTS,
    licenses: Mapping[str, str] = DEFAULT_LICENSES,
) -> RiskReport:
    """Score an individual package based on provided facts and reference date."""
    reasons: list[str] = []
    non_vuln_score = 0

    # Rule 1 & 2: aging_release (366-730 days), stale_release (> 730 days)
    # Unknown last_release adds nothing
    if pkg.last_release is not None:
        age_days = (as_of - pkg.last_release).days
        if age_days > 730:
            non_vuln_score += weights.stale
            reasons.append("stale_release")
        elif age_days >= 366:
            non_vuln_score += weights.aging
            reasons.append("aging_release")

    # Rule 3: single_maintainer (0 or 1 maintainer; null adds nothing)
    if pkg.maintainers is not None and pkg.maintainers <= 1:
        non_vuln_score += weights.single_maintainer
        reasons.append("single_maintainer")

    # Rule 4: deprecated
    if pkg.deprecated:
        non_vuln_score += weights.deprecated
        reasons.append("deprecated")

    # Rule 5, 6, 7: license categories
    category = licenses.get(pkg.license) if pkg.license is not None else None
    if category == "weak_copyleft":
        non_vuln_score += weights.weak_copyleft
        reasons.append("weak_copyleft")
    elif category == "strong_copyleft":
        non_vuln_score += weights.strong_copyleft
        reasons.append("strong_copyleft")
    elif category == "permissive":
        pass
    else:
        # null license, unlisted id, or SPDX expression counts as unknown_license
        non_vuln_score += weights.unknown_license
        reasons.append("unknown_license")

    # Rule 8: vulnerabilities in input order
    vuln_sum = 0
    for vuln in pkg.vulnerabilities:
        if vuln.severity == "critical":
            vuln_sum += weights.critical
        elif vuln.severity == "high":
            vuln_sum += weights.high
        elif vuln.severity == "medium":
            vuln_sum += weights.medium
        elif vuln.severity == "low":
            vuln_sum += weights.low
        reasons.append(f"vulnerability:{vuln.id}:{vuln.severity}")

    capped_vuln_score = min(weights.vuln_cap, vuln_sum)
    final_score = min(100, non_vuln_score + capped_vuln_score)

    level: Literal["low", "medium", "high", "critical"]
    if final_score < 20:
        level = "low"
    elif final_score < 50:
        level = "medium"
    elif final_score < 80:
        level = "high"
    else:
        level = "critical"

    return RiskReport(
        name=pkg.name,
        version=pkg.version,
        score=final_score,
        level=level,
        reasons=tuple(reasons),
    )


def score_all(
    pkgs: list[Package],
    *,
    as_of: date,
    weights: Weights = DEFAULT_WEIGHTS,
    licenses: Mapping[str, str] = DEFAULT_LICENSES,
) -> list[RiskReport]:
    """Score a collection of packages, sorted by score descending then name ascending."""
    reports = [score_package(pkg, as_of=as_of, weights=weights, licenses=licenses) for pkg in pkgs]
    return sorted(reports, key=lambda r: (-r.score, r.name))
