from __future__ import annotations

import uuid

import pytest
from devsecops_shared.models import Finding, Scan, ScanStatus
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

_MISSING_ID = "00000000-0000-0000-0000-000000000000"


def _seed_scan(session: Session, findings: list[dict]) -> uuid.UUID:
    scan = Scan(
        repo_url="https://github.com/example/vulnerable-app",
        status=ScanStatus.DONE,
        commit_sha="b" * 40,
    )
    session.add(scan)
    session.flush()
    session.add_all(
        Finding(
            scan_id=scan.id,
            tool=f.get("tool", "trivy"),
            category=f["category"],
            rule_id=f["rule_id"],
            severity=f["severity"],
            title=f.get("title", f["rule_id"]),
            description=None,
            file_path=f.get("file_path", "Dockerfile"),
            line=f.get("line"),
            package_name=f.get("package_name"),
            installed_version=f.get("installed_version"),
            fixed_version=f.get("fixed_version"),
            raw={"RuleID": f["rule_id"]},
        )
        for f in findings
    )
    session.commit()
    return scan.id


_SAMPLE = [
    {"category": "iac", "rule_id": "DS-0031", "severity": "CRITICAL"},
    {"category": "secret", "rule_id": "aws-access-key-id", "severity": "CRITICAL"},
    {
        "category": "sca",
        "rule_id": "CVE-2019-20477",
        "severity": "HIGH",
        "package_name": "PyYAML",
        "installed_version": "5.1",
        "fixed_version": "5.2",
    },
    {"category": "sast", "rule_id": "python.lang.eval", "severity": "MEDIUM", "tool": "semgrep"},
    {"category": "iac", "rule_id": "KSV-0011", "severity": "LOW"},
]


def test_healthz_needs_no_database() -> None:
    from app.main import app

    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}


def test_readyz_reports_ready(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_post_scan_queues_work(client: TestClient) -> None:
    response = client.post("/scan", json={"repo_url": "https://github.com/octocat/Hello-World"})

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    uuid.UUID(body["scan_id"])


def test_post_scan_canonicalizes_url(client: TestClient) -> None:
    response = client.post("/scan", json={"repo_url": "https://github.com/octocat/Hello-World.git"})
    scan_id = response.json()["scan_id"]

    assert client.get(f"/scans/{scan_id}").json()["repo_url"] == "https://github.com/octocat/Hello-World"


@pytest.mark.parametrize(
    "repo_url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://evilgithub.com/octocat/Hello-World",
        "https://github.com.evil.com/octocat/x",
        "https://user:pass@github.com/octocat/x",
        "ext::sh -c id",
        "not-a-url",
        "https://github.com/",
    ],
)
def test_post_scan_rejects_hostile_urls(client: TestClient, repo_url: str) -> None:
    assert client.post("/scan", json={"repo_url": repo_url}).status_code == 422


def test_get_scan_404_for_unknown_id(client: TestClient) -> None:
    assert client.get(f"/scans/{_MISSING_ID}").status_code == 404


def test_get_scan_422_for_malformed_id(client: TestClient) -> None:
    assert client.get("/scans/not-a-uuid").status_code == 422


def test_report_summary_counts_all_findings(client: TestClient, db_session: Session) -> None:
    scan_id = _seed_scan(db_session, _SAMPLE)

    body = client.get(f"/reports/{scan_id}").json()

    assert body["summary"]["total"] == 5
    assert body["summary"]["by_severity"] == {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 1}
    assert body["summary"]["by_category"] == {"iac": 2, "secret": 1, "sca": 1, "sast": 1}


def test_report_orders_by_severity(client: TestClient, db_session: Session) -> None:
    scan_id = _seed_scan(db_session, _SAMPLE)

    severities = [f["severity"] for f in client.get(f"/reports/{scan_id}").json()["findings"]]

    assert severities == ["CRITICAL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_report_never_exposes_raw(client: TestClient, db_session: Session) -> None:
    scan_id = _seed_scan(db_session, _SAMPLE)

    findings = client.get(f"/reports/{scan_id}").json()["findings"]

    assert findings
    assert all("raw" not in f for f in findings)
    assert all("scan_id" not in f for f in findings)


def test_report_filters_by_severity(client: TestClient, db_session: Session) -> None:
    scan_id = _seed_scan(db_session, _SAMPLE)

    body = client.get(f"/reports/{scan_id}?severity=CRITICAL").json()

    assert body["summary"]["total"] == 2
    assert {f["severity"] for f in body["findings"]} == {"CRITICAL"}


def test_report_filters_by_multiple_categories(client: TestClient, db_session: Session) -> None:
    scan_id = _seed_scan(db_session, _SAMPLE)

    body = client.get(f"/reports/{scan_id}?category=sca&category=sast").json()

    assert body["summary"]["total"] == 2
    assert {f["category"] for f in body["findings"]} == {"sca", "sast"}


def test_report_pagination_does_not_overlap(client: TestClient, db_session: Session) -> None:
    scan_id = _seed_scan(db_session, _SAMPLE)

    page1 = client.get(f"/reports/{scan_id}?limit=2&offset=0").json()
    page2 = client.get(f"/reports/{scan_id}?limit=2&offset=2").json()

    assert page1["summary"]["total"] == 5
    assert len(page1["findings"]) == 2
    assert not {f["id"] for f in page1["findings"]} & {f["id"] for f in page2["findings"]}


@pytest.mark.parametrize("query", ["limit=0", "limit=99999", "offset=-1", "severity=NOPE", "category=nope"])
def test_report_rejects_out_of_range_params(client: TestClient, query: str) -> None:
    assert client.get(f"/reports/{_MISSING_ID}?{query}").status_code == 422


def test_report_404_for_unknown_scan(client: TestClient) -> None:
    assert client.get(f"/reports/{_MISSING_ID}").status_code == 404


def test_list_scans_is_paginated(client: TestClient) -> None:
    for _ in range(3):
        client.post("/scan", json={"repo_url": "https://github.com/octocat/Hello-World"})

    body = client.get("/scans?limit=2").json()

    assert body["total"] == 3
    assert len(body["scans"]) == 2
    assert body["limit"] == 2
