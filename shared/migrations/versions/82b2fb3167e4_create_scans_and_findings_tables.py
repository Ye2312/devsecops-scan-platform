"""create scans and findings tables

Revision ID: 82b2fb3167e4
Revises:
Create Date: 2026-09-03 14:27:00.509110

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "82b2fb3167e4"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repo_url", sa.String(length=2048), nullable=False),
        sa.Column(
            "status",
            sa.Enum("queued", "running", "done", "failed", name="scanstatus", native_enum=False, length=16),
            server_default="queued",
            nullable=False,
        ),
        sa.Column("commit_sha", sa.String(length=40), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('queued', 'running', 'done', 'failed')", name="ck_scans_status"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_status_created_at", "scans", ["status", "created_at"], unique=False)
    op.create_table(
        "findings",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("rule_id", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("package_name", sa.String(length=256), nullable=True),
        sa.Column("installed_version", sa.String(length=128), nullable=True),
        sa.Column("fixed_version", sa.String(length=128), nullable=True),
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_scan_id_severity", "findings", ["scan_id", "severity"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_status_created_at", table_name="scans")
    op.drop_table("scans")
