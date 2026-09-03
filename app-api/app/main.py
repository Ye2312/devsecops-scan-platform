from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated, Literal

from devsecops_shared.db import get_session
from devsecops_shared.models import Finding, Scan
from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import case, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.schemas import (
    FindingRead,
    Report,
    ReportSummary,
    ScanAccepted,
    ScanList,
    ScanRead,
    ScanRequest,
)

app = FastAPI(
    title="devsecops-scan-platform",
    description="SAST + SCA scanning platform for GitHub repositories",
    version="0.1.0",
)

SessionDep = Annotated[Session, Depends(get_session)]

SeverityFilter = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
CategoryFilter = Literal["sast", "sca", "secret", "iac"]

_SEVERITY_RANK = case(
    {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3},
    value=Finding.severity,
    else_=4,
)


@app.get("/healthz", tags=["ops"])
def healthz() -> dict[str, str]:
    """Liveness probe: process is up. Does not touch the database."""
    return {"status": "ok"}


@app.get("/readyz", tags=["ops"])
def readyz(session: SessionDep) -> dict[str, str]:
    """Readiness probe: the process can actually serve traffic."""
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="database unavailable"
        ) from exc
    return {"status": "ready"}


@app.post(
    "/scan",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanAccepted,
    tags=["scans"],
)
def create_scan(payload: ScanRequest, session: SessionDep) -> ScanAccepted:
    """Queue a repository for scanning. Returns immediately; the worker picks it up."""
    scan = Scan(repo_url=payload.repo_url)
    session.add(scan)
    session.commit()
    return ScanAccepted(scan_id=scan.id, status=scan.status)


@app.get("/scans", response_model=ScanList, tags=["scans"])
def list_scans(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanList:
    total = session.scalar(select(func.count()).select_from(Scan)) or 0
    scans = session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)).all()
    return ScanList(
        total=total,
        limit=limit,
        offset=offset,
        scans=[ScanRead.model_validate(s) for s in scans],
    )


@app.get("/scans/{scan_id}", response_model=ScanRead, tags=["scans"])
def get_scan(scan_id: uuid.UUID, session: SessionDep) -> ScanRead:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return ScanRead.model_validate(scan)


@app.get("/reports/{scan_id}", response_model=Report, tags=["reports"])
def get_report(
    scan_id: uuid.UUID,
    session: SessionDep,
    severity: Annotated[list[SeverityFilter] | None, Query()] = None,
    category: Annotated[list[CategoryFilter] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Report:
    """Findings for one scan, most severe first. Summary counts reflect filters, not pagination."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    filters = [Finding.scan_id == scan_id]
    if severity:
        filters.append(Finding.severity.in_(severity))
    if category:
        filters.append(Finding.category.in_(category))

    grouped = session.execute(
        select(Finding.severity, Finding.category, func.count())
        .where(*filters)
        .group_by(Finding.severity, Finding.category)
    ).all()

    by_severity: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    for row_severity, row_category, count in grouped:
        by_severity[row_severity] += count
        by_category[row_category] += count

    findings = session.scalars(
        select(Finding)
        .where(*filters)
        .order_by(_SEVERITY_RANK, Finding.category, Finding.rule_id, Finding.id)
        .limit(limit)
        .offset(offset)
    ).all()

    return Report(
        scan=ScanRead.model_validate(scan),
        summary=ReportSummary(
            total=sum(by_severity.values()),
            by_severity=dict(by_severity),
            by_category=dict(by_category),
        ),
        limit=limit,
        offset=offset,
        findings=[FindingRead.model_validate(f) for f in findings],
    )
