from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from core.schemas import VulnerabilityFinding

BASE_RULES = [
    {
        "id": "py_eval_exec",
        "pattern": re.compile(r"(?<![\"'])\b(eval|exec)\s*\("),
        "extensions": {".py"},
        "severity": "high",
        "type": "unsafe-code-execution",
        "title": "Dynamic code execution detected",
        "fix": "Replace eval/exec with safe parsers and strict allowlists.",
        "scan_mode": "code",
    },
    {
        "id": "shell_true",
        "pattern": re.compile(r"(?<![\"'])subprocess\.(run|Popen)\([^\n]*shell\s*=\s*True"),
        "extensions": {".py"},
        "severity": "high",
        "type": "command-injection",
        "title": "Shell execution with untrusted input risk",
        "fix": "Use argument arrays and shell=False; validate input.",
        "scan_mode": "code",
    },
    {
        "id": "os_system",
        "pattern": re.compile(r"(?<![\"'])\bos\.system\s*\("),
        "extensions": {".py"},
        "severity": "high",
        "type": "command-injection",
        "title": "os.system usage detected",
        "fix": "Use subprocess with strict argument separation.",
        "scan_mode": "code",
    },
    {
        "id": "js_eval",
        "pattern": re.compile(r"(?<![\"'])\beval\s*\("),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "severity": "high",
        "type": "unsafe-code-execution",
        "title": "JavaScript eval usage detected",
        "fix": "Avoid eval; parse structured input with JSON.parse and validation.",
        "scan_mode": "code",
    },
    {
        "id": "child_process_exec",
        "pattern": re.compile(r"(?<![\"'])child_process\.(exec|execSync)\s*\("),
        "extensions": {".js", ".ts"},
        "severity": "high",
        "type": "command-injection",
        "title": "Shell-based child_process usage",
        "fix": "Use spawn/execFile with argument arrays and input validation.",
        "scan_mode": "code",
    },
    {
        "id": "weak_hash",
        "pattern": re.compile(r"\b(md5|sha1)\b", re.IGNORECASE),
        "extensions": {".py", ".js", ".ts", ".go", ".java", ".php", ".rb"},
        "severity": "medium",
        "type": "weak-crypto",
        "title": "Weak hash primitive usage",
        "fix": "Use SHA-256 or stronger modern cryptographic constructions.",
        "scan_mode": "code",
    },
    {
        "id": "weak_random",
        "pattern": re.compile(r"\brandom\.(random|randint|choice)\s*\("),
        "extensions": {".py"},
        "severity": "medium",
        "type": "weak-randomness",
        "title": "Non-cryptographic randomness in security-sensitive context",
        "fix": "Use secrets module for tokens/passwords/security-sensitive randomness.",
        "scan_mode": "code",
    },
    {
        "id": "secret_token",
        "pattern": re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-\./]{8,}['\"]"),
        "extensions": {".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".toml"},
        "severity": "critical",
        "type": "hardcoded-secret",
        "title": "Possible hardcoded secret",
        "fix": "Move secrets to environment variables or a secure secret manager.",
        "scan_mode": "raw",
    },
    {
        "id": "debug_true",
        "pattern": re.compile(r"\bdebug\s*=\s*True\b"),
        "extensions": {".py", ".js", ".ts"},
        "severity": "high",
        "type": "insecure-debug-configuration",
        "title": "Debug mode enabled in code/config",
        "fix": "Disable debug in non-local environments and gate via explicit env flags.",
        "scan_mode": "code",
    },
    {
        "id": "cors_wildcard",
        "pattern": re.compile(r"Access-Control-Allow-Origin[^\n]*\*|cors\([^\n]*\*"),
        "extensions": {".py", ".js", ".ts", ".yaml", ".yml"},
        "severity": "high",
        "type": "cors-misconfiguration",
        "title": "Wildcard CORS policy detected",
        "fix": "Restrict CORS origins to explicit trusted domains.",
        "scan_mode": "raw",
    },
    {
        "id": "sql_concat",
        "pattern": re.compile(r"(?i)(['\"])\s*(select|insert|update|delete)\b[^'\"]*\1\s*\+"),
        "extensions": {".py", ".js", ".ts", ".java", ".php", ".rb", ".go"},
        "severity": "high",
        "type": "sql-injection-risk",
        "title": "SQL string concatenation risk",
        "fix": "Use parameterized queries / prepared statements.",
        "scan_mode": "code",
    },
    {
        "id": "js_innerhtml",
        "pattern": re.compile(r"\.innerHTML\s*="),
        "extensions": {".js", ".ts", ".jsx", ".tsx"},
        "severity": "high",
        "type": "xss-risk",
        "title": "Direct innerHTML assignment detected",
        "fix": "Use safe DOM APIs/textContent or sanitize HTML before insertion.",
        "scan_mode": "code",
    },
    {
        "id": "react_dangerous_html",
        "pattern": re.compile(r"dangerouslySetInnerHTML"),
        "extensions": {".jsx", ".tsx"},
        "severity": "high",
        "type": "xss-risk",
        "title": "dangerouslySetInnerHTML usage detected",
        "fix": "Avoid raw HTML rendering or sanitize with a strict allowlist sanitizer.",
        "scan_mode": "code",
    },
]

STRICT_EXTRA_RULES = [
    {
        "id": "requests_verify_false",
        "pattern": re.compile(r"requests\.(get|post|put|delete|request)\([^\n]*verify\s*=\s*False"),
        "extensions": {".py"},
        "severity": "high",
        "type": "tls-verification-disabled",
        "title": "TLS certificate verification disabled",
        "fix": "Do not set verify=False; configure trust store/cert pinning correctly.",
        "scan_mode": "code",
    },
    {
        "id": "ssl_unverified_context",
        "pattern": re.compile(r"ssl\._create_unverified_context\s*\("),
        "extensions": {".py"},
        "severity": "high",
        "type": "tls-verification-disabled",
        "title": "Unverified SSL context usage",
        "fix": "Use verified SSL context and enforce certificate validation.",
        "scan_mode": "code",
    },
    {
        "id": "yaml_unsafe_load",
        "pattern": re.compile(r"\byaml\.load\s*\("),
        "extensions": {".py"},
        "severity": "high",
        "type": "unsafe-deserialization",
        "title": "Unsafe YAML deserialization",
        "fix": "Use yaml.safe_load for untrusted content.",
        "scan_mode": "code",
    },
    {
        "id": "pickle_loads",
        "pattern": re.compile(r"\bpickle\.loads\s*\("),
        "extensions": {".py"},
        "severity": "high",
        "type": "unsafe-deserialization",
        "title": "Unsafe pickle deserialization",
        "fix": "Avoid pickle for untrusted data; use safe formats like JSON with schema validation.",
        "scan_mode": "code",
    },
    {
        "id": "jwt_none_alg",
        "pattern": re.compile(r"(?i)alg[\"']?\s*[:=]\s*[\"']none[\"']"),
        "extensions": {".py", ".js", ".ts", ".json", ".yaml", ".yml"},
        "severity": "critical",
        "type": "auth-crypto-misconfiguration",
        "title": "JWT none algorithm usage",
        "fix": "Use signed JWT algorithms (e.g., RS256/ES256) and enforce alg allowlist.",
        "scan_mode": "raw",
    },
]

PARANOID_EXTRA_RULES = [
    {
        "id": "todo_security",
        "pattern": re.compile(r"(?i)(todo|fixme|hack).*(security|auth|encrypt|sanitize|validate)"),
        "extensions": {".py", ".js", ".ts", ".go", ".java", ".php", ".rb"},
        "severity": "medium",
        "type": "security-debt",
        "title": "Security TODO/FIXME marker",
        "fix": "Resolve security-related TODO/FIXME before release.",
        "scan_mode": "raw",
    },
    {
        "id": "broad_exception_pass",
        "pattern": re.compile(r"except\s+Exception\s*:\s*pass"),
        "extensions": {".py"},
        "severity": "medium",
        "type": "error-handling-hardening",
        "title": "Broad exception swallowed",
        "fix": "Log and handle exception explicitly; do not silently suppress security-relevant failures.",
        "scan_mode": "code",
    },
]

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".php", ".rb", ".env", ".yaml", ".yml", ".json", ".toml"
}


@dataclass(slots=True)
class SecurityAuditResult:
    findings: list[VulnerabilityFinding]
    files_scanned: int
    language_counts: dict[str, int]


class SecurityAuditEngine:
    def audit(self, target: Path, profile: str = "standard", extra_rules: list[dict] | None = None) -> SecurityAuditResult:
        files = self._collect_files(target)
        findings: list[VulnerabilityFinding] = []
        language_counts: dict[str, int] = {}
        rules = self._rules_for_profile(profile)
        if extra_rules:
            rules.extend(self._normalize_extra_rules(extra_rules))

        for file_path in files:
            ext = file_path.suffix.lower() or "<none>"
            language_counts[ext] = language_counts.get(ext, 0) + 1
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = text.splitlines()
            for idx, line in enumerate(lines, start=1):
                code_line = self._strip_string_literals(line)
                for rule in rules:
                    if file_path.suffix.lower() not in rule["extensions"]:
                        continue
                    scan_line = line if rule.get("scan_mode") == "raw" else code_line
                    if rule["pattern"].search(scan_line):
                        findings.append(
                            VulnerabilityFinding(
                                title=rule["title"],
                                vulnerability_type=rule["type"],
                                severity=rule["severity"],
                                location=f"{file_path}:{idx}",
                                evidence=f"{line.strip()} | Fix: {rule['fix']}",
                                confidence=0.88 if rule["severity"] in {"critical", "high"} else 0.72,
                            )
                        )

        return SecurityAuditResult(findings=findings, files_scanned=len(files), language_counts=language_counts)

    @staticmethod
    def _rules_for_profile(profile: str) -> list[dict]:
        p = profile.lower()
        rules = list(BASE_RULES)
        if p in {"strict", "paranoid"}:
            rules.extend(STRICT_EXTRA_RULES)
        if p == "paranoid":
            rules.extend(PARANOID_EXTRA_RULES)
        return rules

    @staticmethod
    def _normalize_extra_rules(extra_rules: list[dict]) -> list[dict]:
        normalized: list[dict] = []
        for idx, rule in enumerate(extra_rules):
            pattern = rule.get("pattern")
            if not pattern or not isinstance(pattern, str):
                continue
            exts = rule.get("extensions", [])
            if not isinstance(exts, list) or not exts:
                continue
            try:
                compiled = re.compile(pattern)
            except re.error:
                continue
            normalized.append(
                {
                    "id": rule.get("id", f"custom_rule_{idx}"),
                    "pattern": compiled,
                    "extensions": {str(e).lower() for e in exts if isinstance(e, str)},
                    "severity": rule.get("severity", "medium"),
                    "type": rule.get("type", "custom-policy"),
                    "title": rule.get("title", "Custom policy violation"),
                    "fix": rule.get("fix", "Update code to comply with security policy."),
                    "scan_mode": rule.get("scan_mode", "code"),
                }
            )
        return normalized

    @staticmethod
    def _strip_string_literals(line: str) -> str:
        line = re.sub(r"'[^'\\\\]*(?:\\\\.[^'\\\\]*)*'", "''", line)
        line = re.sub(r'"[^"\\\\]*(?:\\\\.[^"\\\\]*)*"', '""', line)
        return line

    def _collect_files(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target] if target.suffix.lower() in SCAN_EXTENSIONS else []

        if not target.is_dir():
            return []

        result: list[Path] = []
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if any(seg.startswith(".") and seg not in {".env"} for seg in p.parts):
                continue
            if "node_modules" in p.parts or ".venv" in p.parts or "dist" in p.parts or "build" in p.parts:
                continue
            if "analysis" in p.parts and "security_audit" in p.parts:
                continue
            if p.suffix.lower() in SCAN_EXTENSIONS:
                result.append(p)
        return result
