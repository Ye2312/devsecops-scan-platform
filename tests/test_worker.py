from __future__ import annotations

import contextlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from devsecops_shared.models import Finding, Scan, ScanStatus
from sqlalchemy import select
from sqlalchemy.orm import Session
from worker import main as worker
from worker.git_clone import CloneFailedError
from worker.normalize import Finding as NormalizedFinding

_REPO = "https://github.com/example/vulnerable-app"


def _add_scan(session: Session, status: ScanStatus, **fields: object) -> Scan:
    scan = Scan(repo_url=_REPO, status=status, **fields)
    session.add(scan)
    session.commit()
    return scan


def _finding(rule_id: str, severity: str) -> NormalizedFinding:
    return NormalizedFinding(
        tool="trivy",
        category="sca",
        rule_id=rule_id,
        severity=severity,
        title=rule_id,
        description=None,
        file_path="requirements.txt",
        line=None,
        package_name="flask",
        installed_version="0.12",
        fixed_version="2.2.5",
        raw={"VulnerabilityID": rule_id},
    )


@pytest.fixture
def fake_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[NormalizedFinding]:
    """Replace cloning and scanning with in-memory fakes; returns the findings the 'scan' will produce."""
    findings = [_finding("CVE-2023-30861", "HIGH"), _finding("CVE-2019-1010083", "CRITICAL")]

    @contextlib.contextmanager
    def fake_clone(url: str) -> Iterator[Path]:
        yield tmp_path

    monkeypatch.setattr(worker, "clone_repository", fake_clone)
    monkeypatch.setattr(worker, "get_head_commit", lambda path: "c" * 40)
    monkeypatch.setattr(worker, "scan_path", lambda path: findings)
    return findings


def test_claim_takes_oldest_queued_scan(db_session: Session) -> None:
    now = datetime.now(UTC)
    _add_scan(db_session, ScanStatus.DONE, created_at=now - timedelta(hours=2))
    oldest = _add_scan(db_session, ScanStatus.QUEUED, created_at=now - timedelta(hours=1))
    _add_scan(db_session, ScanStatus.QUEUED, created_at=now)

    claimed = worker.claim_next_scan(db_session)

    assert claimed is not None
    assert claimed.id == oldest.id
    db_session.refresh(oldest)
    assert oldest.status == ScanStatus.RUNNING
    assert oldest.started_at is not None


def test_claim_returns_none_when_queue_is_empty(db_session: Session) -> None:
    _add_scan(db_session, ScanStatus.RUNNING, started_at=datetime.now(UTC))

    assert worker.claim_next_scan(db_session) is None


def test_requeue_only_touches_stale_running_scans(db_session: Session) -> None:
    now = datetime.now(UTC)
    stale = _add_scan(db_session, ScanStatus.RUNNING, started_at=now - timedelta(hours=2))
    fresh = _add_scan(db_session, ScanStatus.RUNNING, started_at=now - timedelta(minutes=1))

    assert worker.requeue_stale_scans(db_session, timedelta(minutes=30)) == 1

    db_session.refresh(stale)
    db_session.refresh(fresh)
    assert stale.status == ScanStatus.QUEUED
    assert stale.started_at is None
    assert fresh.status == ScanStatus.RUNNING


def test_run_scan_stores_findings(db_session: Session, fake_scan: list[NormalizedFinding]) -> None:
    _add_scan(db_session, ScanStatus.QUEUED)
    claimed = worker.claim_next_scan(db_session)
    assert claimed is not None

    worker.run_scan(claimed)

    db_session.expire_all()
    scan = db_session.get(Scan, claimed.id)
    assert scan is not None
    assert scan.status == ScanStatus.DONE
    assert scan.commit_sha == "c" * 40
    assert scan.finished_at is not None
    stored = db_session.scalars(select(Finding.rule_id).where(Finding.scan_id == claimed.id)).all()
    assert sorted(stored) == sorted(f.rule_id for f in fake_scan)


def test_run_scan_records_failure(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.contextmanager
    def failing_clone(url: str) -> Iterator[Path]:
        raise CloneFailedError("git clone failed: repository not found")
        yield  # pragma: no cover

    monkeypatch.setattr(worker, "clone_repository", failing_clone)
    _add_scan(db_session, ScanStatus.QUEUED)
    claimed = worker.claim_next_scan(db_session)
    assert claimed is not None

    worker.run_scan(claimed)

    db_session.expire_all()
    scan = db_session.get(Scan, claimed.id)
    assert scan is not None
    assert scan.status == ScanStatus.FAILED
    assert scan.error is not None and "repository not found" in scan.error
    assert db_session.scalars(select(Finding).where(Finding.scan_id == claimed.id)).first() is None
