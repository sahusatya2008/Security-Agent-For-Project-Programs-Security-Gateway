from __future__ import annotations

import json
from pathlib import Path

from core.schemas import ExperimentResult


class ReportWriter:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path("reports")

    def write(self, result: ExperimentResult) -> tuple[str, str]:
        out_dir = self.root / result.experiment_id
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / "report.json"
        md_path = out_dir / "report.md"

        payload = result.model_dump(mode="json")
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        md_path.write_text(self._to_markdown(result), encoding="utf-8")

        return str(json_path.resolve()), str(md_path.resolve())

    def _to_markdown(self, result: ExperimentResult) -> str:
        lines: list[str] = []
        lines.append(f"# SNSX CRS Security Report - {result.experiment_id}")
        lines.append("")
        lines.append(f"- Started: {result.started_at}")
        lines.append(f"- Finished: {result.finished_at}")
        lines.append(f"- Target: {result.report.software}")
        lines.append("")
        lines.append("## Risk Summary")
        lines.append(result.report.risk_summary)
        lines.append("")
        lines.append("## Findings")
        if not result.findings:
            lines.append("No findings detected.")
        else:
            for idx, finding in enumerate(result.findings, start=1):
                lines.append(f"### {idx}. {finding.title}")
                lines.append(f"- Type: {finding.vulnerability_type}")
                lines.append(f"- Severity: {finding.severity}")
                lines.append(f"- Location: {finding.location}")
                lines.append(f"- Confidence: {finding.confidence}")
                lines.append(f"- Evidence: {finding.evidence}")
                lines.append("")

        lines.append("## Analysis Artifacts")
        for artifact in result.artifacts:
            lines.append(f"- `{artifact.module}`: {artifact.summary}")

        lines.append("")
        lines.append("## Mitigations")
        for item in result.report.mitigation_strategies:
            lines.append(f"- {item}")

        lines.append("")
        return "\n".join(lines)
