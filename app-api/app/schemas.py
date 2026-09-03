from __future__ import annotations

import uuid
from datetime import datetime

from devsecops_shared.repo_url import InvalidRepoUrlError, canonical_github_url
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanRequest(BaseModel):
    repo_url: str = Field(
        max_length=2048,
        examples=["https://github.com/octocat/Hello-World"],
        description="Public GitHub repository URL to scan.",
    )

    @field_validator("repo_url")
    @classmethod
    def _must_be_a_github_repo(cls, value: str) -> str:
        try:
            return canonical_github_url(value)
        except InvalidRepoUrlError as exc:
            raise ValueError(str(exc)) from exc


class ScanAccepted(BaseModel):
    scan_id: uuid.UUID
    status: str


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    repo_url: str
    status: str
    commit_sha: str | None
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanList(BaseModel):
    total: int
    limit: int
    offset: int
    scans: list[ScanRead]


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
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


class ReportSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]


class Report(BaseModel):
    scan: ScanRead
    summary: ReportSummary
    limit: int
    offset: int
    findings: list[FindingRead]
