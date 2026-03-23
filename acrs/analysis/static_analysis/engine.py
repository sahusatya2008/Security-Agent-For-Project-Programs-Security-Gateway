from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from core.schemas import VulnerabilityFinding

DANGEROUS_CALLS = {"eval", "exec", "pickle.loads", "yaml.load"}


@dataclass(slots=True)
class AnalysisResult:
    summary: str
    data: dict
    findings: list[VulnerabilityFinding]


class VulnerabilityScanner(ast.NodeVisitor):
    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.findings: list[VulnerabilityFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        fn_name = self._resolve_name(node.func)
        if fn_name in DANGEROUS_CALLS:
            self.findings.append(
                VulnerabilityFinding(
                    title="Potential dangerous function call",
                    vulnerability_type="unsafe-code-execution",
                    severity="high",
                    location=f"{self.file_path}:{node.lineno}",
                    evidence=f"Call to `{fn_name}` detected",
                    confidence=0.82,
                )
            )
        self.generic_visit(node)

    @staticmethod
    def _resolve_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = []
            current: ast.AST | None = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return "<unknown>"


class StaticAnalysisEngine:
    def analyze(self, software_path: Path) -> AnalysisResult:
        if software_path.is_file() and software_path.suffix == ".py":
            py_files = [software_path]
        elif software_path.is_dir():
            py_files = [p for p in software_path.rglob("*.py") if p.is_file()]
        else:
            py_files = []
        findings: list[VulnerabilityFinding] = []
        parsed_files = 0

        for file_path in py_files:
            try:
                tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
                scanner = VulnerabilityScanner(file_path)
                scanner.visit(tree)
                findings.extend(scanner.findings)
                parsed_files += 1
            except (SyntaxError, UnicodeDecodeError):
                continue

        data = {
            "scanned_path": str(software_path),
            "python_files_found": len(py_files),
            "python_files_parsed": parsed_files,
            "finding_count": len(findings),
        }
        summary = f"Static analysis scanned {parsed_files} Python files, found {len(findings)} candidate issues."
        return AnalysisResult(summary=summary, data=data, findings=findings)
