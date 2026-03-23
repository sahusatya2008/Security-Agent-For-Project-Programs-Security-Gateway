from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from ai_models.features import FeatureExtractor
from ai_models.model import HeuristicVulnerabilityPredictor
from analysis.binary_analysis.engine import BinaryAnalysisEngine
from analysis.language_detection.engine import LanguageDetectionEngine
from analysis.static_analysis.engine import StaticAnalysisEngine
from analysis.symbolic_execution.engine import SymbolicExecutionEngine
from analysis.web_analysis.engine import WebSharpDetectionEngine
from core.reporting import ReportWriter
from core.schemas import (
    AnalysisArtifact,
    ExperimentReport,
    ExperimentRequest,
    ExperimentResult,
    RemediationRequest,
    RemediationResult,
    VulnerabilityFinding,
)
from core.remediation import RemediationEngine
from exploit_planner.rl_agent import ExploitStrategyPlanner
from fuzzing.agent import FuzzingAgent
from knowledge_graph.graph import SecurityKnowledgeGraph


class ExperimentOrchestrator:
    def __init__(self) -> None:
        self._store: dict[str, ExperimentResult] = {}
        self.static_engine = StaticAnalysisEngine()
        self.language_engine = LanguageDetectionEngine()
        self.web_engine = WebSharpDetectionEngine()
        self.binary_engine = BinaryAnalysisEngine()
        self.symbolic_engine = SymbolicExecutionEngine()
        self.fuzzing_agent = FuzzingAgent()
        self.feature_extractor = FeatureExtractor()
        self.predictor = HeuristicVulnerabilityPredictor()
        self.strategy_planner = ExploitStrategyPlanner()
        self.knowledge_graph = SecurityKnowledgeGraph()
        self.remediation_engine = RemediationEngine()
        self.report_writer = ReportWriter()
        self._experiment_targets: dict[str, Path | None] = {}

    def run(self, request: ExperimentRequest) -> ExperimentResult:
        software_path: Path | None = None
        if request.software_path:
            software_path = Path(request.software_path).expanduser().resolve()
            if not software_path.exists():
                raise FileNotFoundError(f"Software path not found: {software_path}")

        if software_path is None and not (request.sharp_website_detection and request.website_url):
            raise ValueError("Provide software_path or enable sharp_website_detection with website_url.")

        started_at = datetime.now(tz=timezone.utc)
        experiment_id = str(uuid.uuid4())

        findings: list[VulnerabilityFinding] = []
        artifacts: list[AnalysisArtifact] = []
        static_data: dict = {}
        fuzz_data: dict = {}
        detected_languages: dict[str, int] = {}
        scanned_files = 0
        website_profile: dict = {}

        if software_path is not None:
            language_result = self.language_engine.analyze(software_path)
            artifacts.append(
                AnalysisArtifact(module="language_profile", summary=language_result.summary, data=language_result.data)
            )
            detected_languages = language_result.data.get("languages", {})
            scanned_files = int(language_result.data.get("files_scanned", 0))

            static_result = self.static_engine.analyze(software_path)
            artifacts.append(
                AnalysisArtifact(module="static_analysis", summary=static_result.summary, data=static_result.data)
            )
            findings.extend(static_result.findings)
            static_data = static_result.data

        if request.website_url:
            web_max_pages = request.web_max_pages if request.sharp_website_detection else min(10, request.web_max_pages)
            web_max_depth = request.web_max_depth if request.sharp_website_detection else min(1, request.web_max_depth)
            web_result = self.web_engine.analyze(
                request.website_url,
                max_pages=web_max_pages,
                max_depth=web_max_depth,
            )
            artifacts.append(
                AnalysisArtifact(module="web_sharp_detection", summary=web_result.summary, data=web_result.data)
            )
            findings.extend(web_result.findings)
            website_profile = web_result.data

        if request.binary_path and software_path is not None:
            binary_result = self.binary_engine.analyze(Path(request.binary_path).expanduser().resolve())
            artifacts.append(
                AnalysisArtifact(module="binary_analysis", summary=binary_result.summary, data=binary_result.data)
            )
            findings.extend(binary_result.findings)

        if software_path is not None:
            symbolic_result = self.symbolic_engine.analyze(static_data)
            artifacts.append(
                AnalysisArtifact(module="symbolic_execution", summary=symbolic_result.summary, data=symbolic_result.data)
            )
            findings.extend(symbolic_result.findings)

            fuzz_result = self.fuzzing_agent.run(
                harness_command=request.harness_command,
                max_iterations=request.max_fuzz_iterations,
            )
            artifacts.append(AnalysisArtifact(module="fuzzing", summary=fuzz_result.summary, data=fuzz_result.data))
            findings.extend(fuzz_result.findings)
            fuzz_data = fuzz_result.data

            features = self.feature_extractor.extract(static_data, fuzz_data)
            prediction = self.predictor.predict(features)
            artifacts.append(AnalysisArtifact(module="ml_prediction", summary=prediction["summary"], data=prediction))

            strategy = self.strategy_planner.recommend_strategy(static_data, fuzz_data)
            artifacts.append(AnalysisArtifact(module="exploit_strategy", summary=strategy["summary"], data=strategy))

        for finding in findings:
            self.knowledge_graph.add_finding(finding)

        risk_summary = self._risk_summary(findings)
        report = ExperimentReport(
            software=str(software_path) if software_path is not None else (request.website_url or "website-target"),
            generated_at=datetime.now(tz=timezone.utc),
            findings=findings,
            risk_summary=risk_summary,
            mitigation_strategies=self._mitigations(findings),
            detected_languages=detected_languages,
            scanned_files=scanned_files,
            website_profile=website_profile,
        )

        result = ExperimentResult(
            experiment_id=experiment_id,
            started_at=started_at,
            finished_at=datetime.now(tz=timezone.utc),
            artifacts=artifacts,
            findings=findings,
            report=report,
        )
        json_report, md_report = self.report_writer.write(result)
        result.report.json_report_path = json_report
        result.report.markdown_report_path = md_report
        self._store[experiment_id] = result
        self._experiment_targets[experiment_id] = software_path
        return result

    def get(self, experiment_id: str) -> ExperimentResult | None:
        return self._store.get(experiment_id)

    def remediate(self, experiment_id: str, request: RemediationRequest) -> RemediationResult:
        target_path = self._experiment_targets.get(experiment_id)
        if target_path is None:
            raise FileNotFoundError("Experiment has no local filesystem target for remediation.")

        if not target_path.exists():
            raise FileNotFoundError(f"Target path no longer exists: {target_path}")

        allowed_roots = [Path(p).expanduser().resolve() for p in request.allowed_root_paths]
        in_allowed_scope = any(self._is_within(target_path, root) for root in allowed_roots)

        if not request.grant_file_access or not request.allow_write or not in_allowed_scope:
            return RemediationResult(
                experiment_id=experiment_id,
                status="permission_required",
                message=(
                    "File write permission required. Re-submit with grant_file_access=true, "
                    "allow_write=true, and allowed_root_paths including target path."
                ),
                target_path=str(target_path),
                detected_languages={},
                scanned_files=0,
                modified_files=[],
            )

        files = self.remediation_engine.collect_code_files(target_path)
        languages = self.remediation_engine.detect_languages(files)
        modified = self.remediation_engine.remediate_files(files, dry_run=request.dry_run)

        status = "completed" if modified else "no_changes"
        msg = (
            f"Applied remediation to {len(modified)} files."
            if modified
            else "No automatic remediation candidates found."
        )
        if request.dry_run:
            msg = f"Dry run completed. {len(modified)} files would be modified."

        return RemediationResult(
            experiment_id=experiment_id,
            status=status,
            message=msg,
            target_path=str(target_path),
            detected_languages=languages,
            scanned_files=len(files),
            modified_files=modified,
        )

    @staticmethod
    def _is_within(candidate: Path, root: Path) -> bool:
        try:
            candidate.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False

    @staticmethod
    def _risk_summary(findings: list[VulnerabilityFinding]) -> str:
        if not findings:
            return "No high-confidence vulnerabilities detected in this run."
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        return f"Detected {len(findings)} findings (critical={critical}, high={high}, medium={medium})."

    @staticmethod
    def _mitigations(findings: list[VulnerabilityFinding]) -> list[str]:
        if not findings:
            return ["Expand test harness coverage and increase fuzzing corpus diversity."]
        base = {
            "Avoid unsafe dynamic execution (`eval`, `exec`) and sanitize untrusted input.",
            "Apply strict bounds checking for memory and buffer operations.",
            "Harden parsing logic and add negative tests for malformed input.",
            "Enable compiler hardening, sanitizer builds, and continuous fuzzing in CI.",
        }
        return sorted(base)
