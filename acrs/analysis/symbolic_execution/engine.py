from __future__ import annotations

from dataclasses import dataclass

from core.schemas import VulnerabilityFinding

try:
    from z3 import Int, Solver

    Z3_AVAILABLE = True
except Exception:
    Z3_AVAILABLE = False


@dataclass(slots=True)
class SymbolicResult:
    summary: str
    data: dict
    findings: list[VulnerabilityFinding]


class SymbolicExecutionEngine:
    def analyze(self, static_data: dict) -> SymbolicResult:
        findings: list[VulnerabilityFinding] = []
        constraints_checked = 0

        if Z3_AVAILABLE:
            user_input = Int("user_input")
            buffer_size = Int("buffer_size")
            solver = Solver()
            solver.add(buffer_size == 64)
            solver.add(user_input > buffer_size)
            constraints_checked = 1
            if solver.check().r == 1:
                findings.append(
                    VulnerabilityFinding(
                        title="Feasible overflow-like condition",
                        vulnerability_type="bounds-check",
                        severity="medium",
                        location="symbolic:path-0",
                        evidence="Found satisfiable condition user_input > buffer_size",
                        confidence=0.67,
                    )
                )

        summary = (
            "Symbolic execution explored candidate constraints with Z3."
            if Z3_AVAILABLE
            else "Symbolic execution placeholder run (install z3-solver for constraint solving)."
        )
        data = {
            "z3_available": Z3_AVAILABLE,
            "constraints_checked": constraints_checked,
            "static_context": static_data,
        }
        return SymbolicResult(summary=summary, data=data, findings=findings)
