import json
from pathlib import Path

import pytest
from worker.normalize import (
    _SEMGREP_SEVERITY_MAP,
    _normalize_severity,
    normalize_all,
    normalize_semgrep,
    normalize_trivy,
)

_SAMPLES = Path(__file__).parent / "fixtures" / "tool_output"


@pytest.fixture(scope="module")
def semgrep_results() -> list[dict]:
    return json.loads((_SAMPLES / "semgrep_sample.json").read_text())


@pytest.fixture(scope="module")
def trivy_results() -> list[dict]:
    return json.loads((_SAMPLES / "trivy_sample.json").read_text())


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ERROR", "HIGH"),
        ("WARNING", "MEDIUM"),
        ("INFO", "LOW"),
        ("CRITICAL", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("MEDIUM", "MEDIUM"),
        ("LOW", "LOW"),
        ("error", "HIGH"),
        ("critical", "CRITICAL"),
        ("EXPERIMENT", "UNKNOWN"),
        ("", "UNKNOWN"),
    ],
)
def test_semgrep_severity_mapping(value: str, expected: str) -> None:
    assert _normalize_severity(value, _SEMGREP_SEVERITY_MAP) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CRITICAL", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("UNKNOWN", "UNKNOWN"),
        ("nonsense", "UNKNOWN"),
        ("", "UNKNOWN"),
    ],
)
def test_trivy_severity_passthrough(value: str, expected: str) -> None:
    assert _normalize_severity(value) == expected


def test_semgrep_findings_are_sast(semgrep_results: list[dict]) -> None:
    findings = normalize_semgrep(semgrep_results)

    assert len(findings) == len(semgrep_results)
    assert {f.tool for f in findings} == {"semgrep"}
    assert {f.category for f in findings} == {"sast"}
    assert all(f.severity != "UNKNOWN" for f in findings)
    assert all(f.file_path and not f.file_path.startswith("/") for f in findings)
    assert all(f.line and f.line > 0 for f in findings)
    assert all(f.package_name is None for f in findings)


def test_trivy_splits_into_three_categories(trivy_results: list[dict]) -> None:
    findings = normalize_trivy(trivy_results)

    assert {f.tool for f in findings} == {"trivy"}
    assert {f.category for f in findings} == {"sca", "secret", "iac"}
    assert all(f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} for f in findings)


def test_sca_findings_carry_package_versions(trivy_results: list[dict]) -> None:
    sca = [f for f in normalize_trivy(trivy_results) if f.category == "sca"]

    assert sca
    for finding in sca:
        assert finding.rule_id.startswith("CVE-")
        assert finding.package_name
        assert finding.installed_version
        assert finding.line is None


def test_iac_and_secret_findings_have_locations(trivy_results: list[dict]) -> None:
    findings = normalize_trivy(trivy_results)

    for finding in findings:
        if finding.category in {"secret", "iac"}:
            assert finding.file_path


def test_raw_never_contains_verbatim_source(trivy_results: list[dict]) -> None:
    """Trivy embeds unmasked file content in Code blocks; it must not reach `raw`."""
    findings = normalize_trivy(trivy_results)
    blob = json.dumps([f.raw for f in findings])

    assert "AKIAZ3X9K2M4NQPLW8RT" not in blob
    assert "Code" not in blob


def test_raw_preserves_tool_detail(trivy_results: list[dict]) -> None:
    sca = next(f for f in normalize_trivy(trivy_results) if f.category == "sca")

    assert sca.raw["VulnerabilityID"] == sca.rule_id
    assert "Description" in sca.raw


def test_normalize_all_merges_both_tools(semgrep_results: list[dict], trivy_results: list[dict]) -> None:
    combined = normalize_all(semgrep_results, trivy_results)

    assert len(combined) == len(normalize_semgrep(semgrep_results)) + len(normalize_trivy(trivy_results))
    assert {f.tool for f in combined} == {"semgrep", "trivy"}


def test_normalize_handles_empty_input() -> None:
    assert normalize_all([], []) == []
