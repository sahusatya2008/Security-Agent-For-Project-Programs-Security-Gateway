from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.schemas import VulnerabilityFinding


@dataclass(slots=True)
class BinaryAnalysisResult:
    summary: str
    data: dict
    findings: list[VulnerabilityFinding]


class BinaryAnalysisEngine:
    def analyze(self, binary_path: Path) -> BinaryAnalysisResult:
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        size = binary_path.stat().st_size
        findings: list[VulnerabilityFinding] = []
        if size == 0:
            findings.append(
                VulnerabilityFinding(
                    title="Empty binary artifact",
                    vulnerability_type="analysis-integrity",
                    severity="low",
                    location=str(binary_path),
                    evidence="Binary file has zero size",
                    confidence=0.9,
                )
            )

        data = {
            "binary_path": str(binary_path),
            "size_bytes": size,
            "disassembler_adapter": "pending-ghidra-r2-integration",
            "cfg_reconstructed": False,
        }
        summary = "Binary analysis adapter executed with metadata extraction."
        return BinaryAnalysisResult(summary=summary, data=data, findings=findings)
