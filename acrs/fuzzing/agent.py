from __future__ import annotations

import secrets
import subprocess
from dataclasses import dataclass

from core.schemas import VulnerabilityFinding
from fuzzing.mutators import bit_flip, dictionary_insertion, structure_mutation


@dataclass(slots=True)
class FuzzingResult:
    summary: str
    data: dict
    findings: list[VulnerabilityFinding]


class FuzzingAgent:
    def run(self, harness_command: str | None, max_iterations: int = 50) -> FuzzingResult:
        seed = b"seed_input"
        crashes = 0
        unique_failures: set[str] = set()
        findings: list[VulnerabilityFinding] = []

        for i in range(max_iterations):
            candidate = secrets.choice(
                [bit_flip(seed), dictionary_insertion(seed), structure_mutation(seed)]
            )
            if harness_command:
                proc = subprocess.run(
                    harness_command,
                    shell=True,
                    input=candidate,
                    capture_output=True,
                    timeout=2,
                )
                if proc.returncode != 0:
                    crashes += 1
                    signature = proc.stderr.decode("utf-8", errors="ignore")[:120]
                    unique_failures.add(signature)

            # Heuristic anomaly signal.
            if b"../" in candidate or b"%x%x%x" in candidate:
                findings.append(
                    VulnerabilityFinding(
                        title="Potential parser/input handling weakness",
                        vulnerability_type="input-validation",
                        severity="medium",
                        location=f"fuzzing:iteration-{i}",
                        evidence="Mutated payload triggered suspicious pattern",
                        confidence=0.45,
                    )
                )

        data = {
            "iterations": max_iterations,
            "crash_count": crashes,
            "unique_failures": len(unique_failures),
            "harness_used": bool(harness_command),
        }
        summary = f"Fuzzing completed {max_iterations} iterations with {crashes} crashes observed."
        return FuzzingResult(summary=summary, data=data, findings=findings)
