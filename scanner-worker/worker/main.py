from __future__ import annotations

import logging
import signal
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import FrameType

from devsecops_shared.config import settings
from devsecops_shared.db import SessionLocal
from devsecops_shared.models import Finding, Scan, ScanStatus
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from worker.cli import scan_path
from worker.git_clone import CloneFailedError, InvalidRepoUrlError, clone_repository, get_head_commit
from worker.normalize import Finding as NormalizedFinding
from worker.semgrep_runner import SemgrepScanError
from worker.trivy_runner import TrivyScanError

log = logging.getLogger("worker")

_MAX_ERROR_LENGTH = 4000

# Errors that mean "this repository can't be scanned", as opposed to a bug in the worker.
SCAN_ERRORS = (InvalidRepoUrlError, CloneFailedError, SemgrepScanError, TrivyScanError)

_shutdown = threading.Event()


def _handle_signal(signum: int, frame: FrameType | None) -> None:
    log.info("received signal %s, finishing current task", signum)
    _shutdown.set()


@dataclass(frozen=True)
class ClaimedScan:
    id: uuid.UUID
    repo_url: str


def requeue_stale_scans(session: Session, stale_after: timedelta) -> int:
    """Put scans orphaned by a crashed worker back in the queue."""
    cutoff = datetime.now(UTC) - stale_after
    result = session.execute(
        update(Scan)
        .where(Scan.status == ScanStatus.RUNNING, Scan.started_at < cutoff)
        .values(status=ScanStatus.QUEUED, started_at=None)
    )
    session.commit()
    return result.rowcount  # type: ignore[attr-defined, no-any-return]


def claim_next_scan(session: Session) -> ClaimedScan | None:
    """Atomically take the oldest queued scan and mark it RUNNING.

    FOR UPDATE SKIP LOCKED lets several workers poll the same table without
    double-processing a scan or blocking on each other's row locks.
    """
    scan = session.scalars(
        select(Scan)
        .where(Scan.status == ScanStatus.QUEUED)
        .order_by(Scan.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    ).first()
    if scan is None:
        session.rollback()
        return None

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(UTC)
    session.commit()
    return ClaimedScan(id=scan.id, repo_url=scan.repo_url)


def _to_row(scan_id: uuid.UUID, finding: NormalizedFinding) -> Finding:
    return Finding(
        scan_id=scan_id,
        tool=finding.tool,
        category=finding.category,
        rule_id=finding.rule_id,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        file_path=finding.file_path,
        line=finding.line,
        package_name=finding.package_name,
        installed_version=finding.installed_version,
        fixed_version=finding.fixed_version,
        raw=finding.raw,
    )


def run_scan(claimed: ClaimedScan) -> None:
    """Clone, scan and store results for one claimed scan; record failure instead of raising."""
    try:
        with clone_repository(claimed.repo_url) as repo_path:
            commit = get_head_commit(repo_path)
            findings = scan_path(repo_path)
    except SCAN_ERRORS as exc:
        log.warning("scan %s failed: %s", claimed.id, exc)
        _finish(claimed.id, ScanStatus.FAILED, error=str(exc))
        return
    except Exception:
        log.exception("scan %s crashed", claimed.id)
        _finish(claimed.id, ScanStatus.FAILED, error="internal worker error")
        return

    _finish(claimed.id, ScanStatus.DONE, commit=commit, findings=findings)
    log.info("scan %s done: %d findings", claimed.id, len(findings))


def _finish(
    scan_id: uuid.UUID,
    status: ScanStatus,
    *,
    commit: str | None = None,
    findings: list[NormalizedFinding] | None = None,
    error: str | None = None,
) -> None:
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            log.warning("scan %s disappeared before its results were saved", scan_id)
            return
        scan.status = status
        scan.commit_sha = commit
        scan.error = error[:_MAX_ERROR_LENGTH] if error else None
        scan.finished_at = datetime.now(UTC)
        session.add_all(_to_row(scan_id, f) for f in findings or [])
        session.commit()


def run_forever() -> None:
    stale_after = timedelta(seconds=settings.worker_stale_after_seconds)
    while not _shutdown.is_set():
        with SessionLocal() as session:
            requeued = requeue_stale_scans(session, stale_after)
            if requeued:
                log.warning("re-queued %d stale scan(s)", requeued)
            claimed = claim_next_scan(session)

        if claimed is None:
            _shutdown.wait(settings.worker_poll_interval_seconds)
            continue

        log.info("scan %s started: %s", claimed.id, claimed.repo_url)
        run_scan(claimed)


def main() -> None:
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    log.info("worker started")
    run_forever()
    log.info("worker stopped")


if __name__ == "__main__":
    main()
