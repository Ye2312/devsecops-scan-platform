from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base for all ORM models."""


class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


_STATUS_IN_CLAUSE = ", ".join(f"'{member.value}'" for member in ScanStatus)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    repo_url: Mapped[str] = mapped_column(String(2048))
    status: Mapped[ScanStatus] = mapped_column(
        Enum(
            ScanStatus,
            native_enum=False,
            create_constraint=False,
            length=16,
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        default=ScanStatus.QUEUED,
        server_default=ScanStatus.QUEUED.value,
    )
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        CheckConstraint(f"status IN ({_STATUS_IN_CLAUSE})", name="ck_scans_status"),
        Index("ix_scans_status_created_at", "status", "created_at"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))

    tool: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(16))
    rule_id: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)

    file_path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)

    package_name: Mapped[str | None] = mapped_column(String(256))
    installed_version: Mapped[str | None] = mapped_column(String(128))
    fixed_version: Mapped[str | None] = mapped_column(String(128))

    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)

    scan: Mapped[Scan] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_findings_scan_id_severity", "scan_id", "severity"),)
