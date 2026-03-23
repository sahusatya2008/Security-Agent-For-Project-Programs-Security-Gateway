from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote
import re

from pydantic import BaseModel, Field, field_validator


Severity = Literal["info", "low", "medium", "high", "critical"]


class VulnerabilityFinding(BaseModel):
    title: str
    vulnerability_type: str
    severity: Severity = "info"
    location: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)


class AnalysisArtifact(BaseModel):
    module: str
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)


class ExperimentRequest(BaseModel):
    software_path: str | None = None
    language: str = "unknown"
    website_url: str | None = None
    sharp_website_detection: bool = False
    web_max_pages: int = Field(default=20, ge=1, le=200)
    web_max_depth: int = Field(default=1, ge=0, le=4)
    binary_path: str | None = None
    harness_command: str | None = None
    max_fuzz_iterations: int = Field(default=50, ge=1, le=10_000)

    @field_validator("software_path", mode="before")
    @classmethod
    def normalize_software_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            return value

        raw = value.strip().strip("\"'")
        if not raw:
            return None
        if Path(raw).expanduser().exists():
            return raw

        candidates: list[str] = []
        candidates.extend(re.findall(r"`([^`]+)`", raw))
        candidates.extend(re.findall(r"\((/[^)]+)\)", raw))
        candidates.extend(re.findall(r"(/[^\\n\\r\\)\\]\"]+)", raw))

        normalized: list[str] = []
        for candidate in candidates:
            c = unquote(candidate.strip().strip("\"'"))
            c = c.rstrip(".,;:)}]")
            if c:
                normalized.append(c)

        existing = [p for p in normalized if Path(p).expanduser().exists()]
        if existing:
            return max(existing, key=len)

        if normalized:
            return normalized[0]

        return raw


class ExperimentReport(BaseModel):
    software: str
    generated_at: datetime
    findings: list[VulnerabilityFinding]
    risk_summary: str
    mitigation_strategies: list[str]
    detected_languages: dict[str, int] = Field(default_factory=dict)
    scanned_files: int = 0
    website_profile: dict[str, Any] = Field(default_factory=dict)
    json_report_path: str | None = None
    markdown_report_path: str | None = None


class ExperimentResult(BaseModel):
    experiment_id: str
    started_at: datetime
    finished_at: datetime
    artifacts: list[AnalysisArtifact]
    findings: list[VulnerabilityFinding]
    report: ExperimentReport


RemediationStatus = Literal["permission_required", "completed", "no_changes", "failed"]


class RemediationRequest(BaseModel):
    grant_file_access: bool = False
    allow_write: bool = False
    allowed_root_paths: list[str] = Field(default_factory=list)
    dry_run: bool = False


class FileRemediation(BaseModel):
    file_path: str
    language: str
    changes_applied: list[str]
    backup_path: str | None = None


class RemediationResult(BaseModel):
    experiment_id: str
    status: RemediationStatus
    message: str
    target_path: str
    detected_languages: dict[str, int]
    scanned_files: int
    modified_files: list[FileRemediation] = Field(default_factory=list)
