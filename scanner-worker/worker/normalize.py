from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}

_KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


@dataclass(frozen=True)
class Finding:
    tool: str
    category: str
    rule_id: str
    severity: str
    title: str
    description: str | None
    file_path: str | None
    line: int | None
    package_name: str | None
    installed_version: str | None
    fixed_version: str | None
    raw: dict[str, Any]


def _normalize_severity(value: str, mapping: dict[str, str] | None = None) -> str:
    if mapping is not None:
        value = mapping.get(value, "UNKNOWN")
    value = value.upper()
    return value if value in _KNOWN_SEVERITIES else "UNKNOWN"


def normalize_semgrep(results: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for r in results:
        extra = r.get("extra", {})
        findings.append(
            Finding(
                tool="semgrep",
                category="sast",
                rule_id=r["check_id"],
                severity=_normalize_severity(extra.get("severity", ""), _SEMGREP_SEVERITY_MAP),
                title=r["check_id"],
                description=extra.get("message"),
                file_path=r.get("path"),
                line=r.get("start", {}).get("line"),
                package_name=None,
                installed_version=None,
                fixed_version=None,
                raw=r,
            )
        )
    return findings


def normalize_trivy(results: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for result in results:
        target = result.get("Target")

        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    tool="trivy",
                    category="sca",
                    rule_id=vuln["VulnerabilityID"],
                    severity=_normalize_severity(vuln.get("Severity", "")),
                    title=vuln.get("Title") or vuln["VulnerabilityID"],
                    description=vuln.get("Description"),
                    file_path=target,
                    line=None,
                    package_name=vuln.get("PkgName"),
                    installed_version=vuln.get("InstalledVersion"),
                    fixed_version=vuln.get("FixedVersion"),
                    raw=vuln,
                )
            )

        for secret in result.get("Secrets") or []:
            findings.append(
                Finding(
                    tool="trivy",
                    category="secret",
                    rule_id=secret["RuleID"],
                    severity=_normalize_severity(secret.get("Severity", "")),
                    title=secret.get("Title") or secret["RuleID"],
                    description=None,
                    file_path=target,
                    line=secret.get("StartLine"),
                    package_name=None,
                    installed_version=None,
                    fixed_version=None,
                    raw=secret,
                )
            )

        for misconfig in result.get("Misconfigurations") or []:
            cause = misconfig.get("CauseMetadata") or {}
            findings.append(
                Finding(
                    tool="trivy",
                    category="iac",
                    rule_id=misconfig["ID"],
                    severity=_normalize_severity(misconfig.get("Severity", "")),
                    title=misconfig.get("Title") or misconfig["ID"],
                    description=misconfig.get("Message") or misconfig.get("Description"),
                    file_path=target,
                    line=cause.get("StartLine"),
                    package_name=None,
                    installed_version=None,
                    fixed_version=None,
                    raw=misconfig,
                )
            )
    return findings


def normalize_all(
    semgrep_results: list[dict[str, Any]], trivy_results: list[dict[str, Any]]
) -> list[Finding]:
    return normalize_semgrep(semgrep_results) + normalize_trivy(trivy_results)
