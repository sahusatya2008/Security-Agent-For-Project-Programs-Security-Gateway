from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from analysis.security_audit.engine import SecurityAuditEngine
from core.pipeline import ExperimentOrchestrator
from core.schemas import ExperimentRequest, RemediationRequest, VulnerabilityFinding

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="snsx", description="SNSX CRS terminal security scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run full experiment against local path and/or website URL")
    scan.add_argument("--path", nargs="+", help="Local file or directory path to scan", default=None)
    scan.add_argument("--url", help="Authorized website URL to scan", default=None)
    scan.add_argument("--sharp-web", action="store_true", help="Enable sharp website security checks")
    scan.add_argument("--web-max-pages", type=int, default=20)
    scan.add_argument("--web-max-depth", type=int, default=1)
    scan.add_argument("--language", default="unknown")
    scan.add_argument("--binary-path", default=None)
    scan.add_argument("--fuzz-iterations", type=int, default=50)
    scan.add_argument("--auto-remediate", action="store_true", help="Apply auto remediation after scan")
    scan.add_argument("--dry-run-remediation", action="store_true", help="Do not write files during remediation")
    scan.add_argument("--output", default=None, help="Write scan JSON to output file")

    audit = sub.add_parser("audit", help="Fast file-level security audit with file:line findings")
    audit.add_argument("--path", nargs="+", required=True, help="Path to project file/folder")
    audit.add_argument("--profile", default="strict", choices=["standard", "strict", "paranoid"])
    audit.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])
    audit.add_argument("--output", default=None)

    guard = sub.add_parser("guard-run", help="Block command execution when security findings exist")
    guard.add_argument("--path", nargs="+", required=True, help="Path to project file/folder")
    guard.add_argument("--profile", default="strict", choices=["standard", "strict", "paranoid"])
    guard.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])
    guard.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run after '--'")

    watch = sub.add_parser("watch", help="Continuously audit directory and print new findings")
    watch.add_argument("--path", nargs="+", required=True)
    watch.add_argument("--interval", type=int, default=5)
    watch.add_argument("--profile", default="strict", choices=["standard", "strict", "paranoid"])
    watch.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])

    hook = sub.add_parser("print-zsh-hook", help="Print zsh hook snippet for guard enforcement")
    hook.add_argument("--path", nargs="+", default=["."])
    hook.add_argument("--profile", default="strict", choices=["standard", "strict", "paranoid"])
    hook.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])

    init = sub.add_parser("init", help="Bind SNSX guard policy to a project directory")
    init.add_argument("--path", nargs="+", required=True, help="Project root path")
    init.add_argument("--profile", default="strict", choices=["standard", "strict", "paranoid"])
    init.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])

    uninstall = sub.add_parser("uninstall", help="Remove SNSX project binding created by init")
    uninstall.add_argument("--path", nargs="+", required=True, help="Project root path")

    return parser


def _filter_findings(findings: list[VulnerabilityFinding], min_severity: str) -> list[VulnerabilityFinding]:
    floor = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= floor]


def _path_value(raw: str | list[str] | None) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    return " ".join(raw).strip() or None


def _load_policy(project_root: Path) -> dict:
    policy_path = project_root / ".snsx" / "policy.json"
    if not policy_path.exists():
        return {}
    try:
        return json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _git_branch(project_root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=3,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return os.getenv("GIT_BRANCH", "")


def _effective_security_settings(args: argparse.Namespace, policy: dict, project_root: Path) -> tuple[str, str]:
    profile = getattr(args, "profile", "strict")
    min_severity = getattr(args, "min_severity", "low")

    if isinstance(policy.get("profile"), str):
        profile = policy["profile"]
    if isinstance(policy.get("min_severity"), str):
        min_severity = policy["min_severity"]

    branch = _git_branch(project_root)
    branch_gates = policy.get("branch_gates", {})
    if isinstance(branch_gates, dict) and branch in branch_gates and isinstance(branch_gates[branch], dict):
        gate = branch_gates[branch]
        if isinstance(gate.get("profile"), str):
            profile = gate["profile"]
        if isinstance(gate.get("min_severity"), str):
            min_severity = gate["min_severity"]

    env_name = os.getenv("SNSX_ENV", os.getenv("ENVIRONMENT", "")).strip()
    env_gates = policy.get("environment_gates", {})
    if isinstance(env_gates, dict) and env_name in env_gates and isinstance(env_gates[env_name], dict):
        gate = env_gates[env_name]
        if isinstance(gate.get("profile"), str):
            profile = gate["profile"]
        if isinstance(gate.get("min_severity"), str):
            min_severity = gate["min_severity"]

    return profile, min_severity


def _run_required_commands(project_root: Path, checks: list[dict], label: str) -> list[str]:
    failures: list[str] = []
    for check in checks:
        name = check.get("name", label)
        cmd = check.get("cmd")
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        proc = subprocess.run(["zsh", "-lc", cmd], cwd=str(project_root))
        if proc.returncode != 0:
            failures.append(f"{label}:{name} failed (exit={proc.returncode})")
    return failures


def _findings_to_text(findings: list[VulnerabilityFinding]) -> str:
    lines = []
    for f in findings:
        fix = _fix_plan_for_finding(f)
        lines.append(f"[{f.severity.upper()}] {f.title}")
        lines.append(f"  - Location: {f.location}")
        lines.append(f"  - Type: {f.vulnerability_type}")
        lines.append(f"  - Evidence: {f.evidence}")
        lines.append(f"  - What to do: {fix['what_to_change']}")
        lines.append(f"  - Example fix:")
        lines.append(f"      before: {fix['example_before']}")
        lines.append(f"      after : {fix['example_after']}")
    return "\n".join(lines)


def _location_parts(location: str) -> tuple[str, int | None]:
    m = re.match(r"^(.*?):(\d+)$", location)
    if not m:
        return location, None
    return m.group(1), int(m.group(2))


def _line_excerpt(file_path: str, line_no: int | None) -> str:
    if line_no is None:
        return ""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1].strip()
    except Exception:
        return ""
    return ""


def _fix_plan_for_finding(f: VulnerabilityFinding) -> dict[str, str]:
    file_path, line_no = _location_parts(f.location)
    excerpt = _line_excerpt(file_path, line_no)

    if f.vulnerability_type == "command-injection" and "shell" in f.title.lower():
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Remove shell=True and pass command arguments as a list after input validation.",
            "example_before": "subprocess.run(f\"echo {user_input}\", shell=True, capture_output=True, text=True)",
            "example_after": "subprocess.run([\"echo\", safe_user_input], shell=False, check=True, capture_output=True, text=True)",
            "verify": "Run unit tests with payloads containing shell metacharacters and confirm no command expansion.",
        }

    if f.vulnerability_type == "command-injection":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Replace shell command construction with argument-safe subprocess APIs.",
            "example_before": "os.system(cmd)",
            "example_after": "subprocess.run(shlex.split(cmd), shell=False, check=True)",
            "verify": "Add tests that pass malicious input and assert command execution is constrained.",
        }

    if f.vulnerability_type == "unsafe-code-execution":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Eliminate eval/exec and use safe parsing with explicit allowlists.",
            "example_before": "result = eval(expr)",
            "example_after": "result = ast.literal_eval(expr)  # for trusted literal formats only",
            "verify": "Test with payloads like '__import__(\"os\").system(\"id\")' and ensure they fail safely.",
        }

    if f.vulnerability_type == "hardcoded-secret":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Remove embedded credentials and load from environment/secret manager.",
            "example_before": "API_KEY = \"sk_live_...\"",
            "example_after": "API_KEY = os.environ[\"API_KEY\"]",
            "verify": "Rotate exposed secret, ensure app fails fast when env secret is missing.",
        }

    if f.vulnerability_type == "weak-crypto":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Replace weak hash primitives (MD5/SHA1) with SHA-256+ or modern KDFs.",
            "example_before": "hashlib.md5(data).hexdigest()",
            "example_after": "hashlib.sha256(data).hexdigest()",
            "verify": "Recompute and validate downstream compatibility with upgraded hash algorithm.",
        }

    if f.vulnerability_type == "weak-randomness":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Use cryptographically secure randomness for secrets/tokens.",
            "example_before": "token = str(random.randint(100000, 999999))",
            "example_after": "token = secrets.token_urlsafe(32)",
            "verify": "Ensure all security tokens/session secrets use `secrets` or crypto-safe APIs.",
        }

    if f.vulnerability_type == "insecure-debug-configuration":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Disable debug in production and control via env-based config.",
            "example_before": "app.run(debug=True)",
            "example_after": "app.run(debug=os.getenv(\"APP_DEBUG\", \"0\") == \"1\")",
            "verify": "Validate production env sets debug to false and error pages hide stack traces.",
        }

    if f.vulnerability_type == "cors-misconfiguration":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Replace wildcard CORS with explicit origin allowlist.",
            "example_before": "CORS(app, resources={r\"/*\": {\"origins\": \"*\"}})",
            "example_after": "CORS(app, resources={r\"/*\": {\"origins\": [\"https://app.example.com\"]}})",
            "verify": "Test cross-origin requests from untrusted origins are denied.",
        }

    if f.vulnerability_type == "xss-risk":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Avoid raw HTML injection; sanitize or render as plain text.",
            "example_before": "element.innerHTML = userInput",
            "example_after": "element.textContent = userInput",
            "verify": "Inject `<script>` payloads and confirm no script execution.",
        }

    if f.vulnerability_type == "sql-injection-risk":
        return {
            "where": f.location,
            "line_excerpt": excerpt,
            "what_to_change": "Replace SQL string concatenation with parameterized queries.",
            "example_before": "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)",
            "example_after": "cursor.execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))",
            "verify": "Test with payloads like \"1 OR 1=1\" and ensure query behavior remains safe.",
        }

    return {
        "where": f.location,
        "line_excerpt": excerpt,
        "what_to_change": "Apply secure coding best practices and add regression tests.",
        "example_before": "<current line>",
        "example_after": "<safe implementation>",
        "verify": "Re-run snsx audit and project tests to ensure finding is resolved.",
    }


def _hardening_recommendations(findings: list[VulnerabilityFinding], language_counts: dict[str, int]) -> list[str]:
    recs: list[str] = []
    kinds = {f.vulnerability_type for f in findings}

    recs.append("Enable CI security gate: `snsx audit --path . --min-severity medium` and block merge on non-zero exit.")
    recs.append("Adopt signed dependency lockfiles and routine dependency vulnerability scanning.")

    if any(ext in language_counts for ext in [".py", ".js", ".ts", ".java", ".go", ".rb", ".php"]):
        recs.append("Add SAST + unit tests covering input validation, authz checks, and negative security cases.")

    if "hardcoded-secret" in kinds:
        recs.append("Move secrets to vault/env manager and rotate exposed credentials immediately.")
    if "command-injection" in kinds:
        recs.append("Ban shell execution wrappers in code review policy; enforce argument-safe subprocess APIs.")
    if "sql-injection-risk" in kinds:
        recs.append("Mandate parameterized queries and ORM safe query builders.")
    if "xss-risk" in kinds:
        recs.append("Enforce output encoding and CSP with strict script-src policy.")
    if "cors-misconfiguration" in kinds:
        recs.append("Define explicit CORS allowlist per environment and endpoint sensitivity.")
    if "insecure-debug-configuration" in kinds:
        recs.append("Harden runtime configuration profile: debug off, safe error handling, secure logging.")
    if "weak-randomness" in kinds or "weak-crypto" in kinds:
        recs.append("Use approved crypto primitives only (SHA-256+, strong RNG, modern KDFs).")

    recs.append("Re-run `snsx audit` after fixes and require 0 findings at chosen policy threshold before release.")
    return recs


def _enforce_required_headers(scan_payload: dict, required_headers: list[str]) -> list[dict]:
    if not required_headers:
        return []
    report = scan_payload.get("report", {})
    profile = report.get("website_profile", {}) if isinstance(report, dict) else {}
    pages = profile.get("pages", []) if isinstance(profile, dict) else []
    missing: list[dict] = []
    if not pages:
        return missing

    findings = scan_payload.get("findings", [])
    findings_text = json.dumps(findings).lower()
    for page in pages:
        url = page.get("url", "<unknown>")
        for header in required_headers:
            key = str(header).lower()
            if key in findings_text:
                missing.append({"url": url, "header": header})
    return missing


def _run_scan(args: argparse.Namespace) -> int:
    orchestrator = ExperimentOrchestrator()
    scan_path = _path_value(args.path)
    if scan_path:
        p = Path(scan_path).expanduser().resolve()
        project_root = p if p.is_dir() else p.parent
    else:
        project_root = Path.cwd().resolve()
    policy = _load_policy(project_root)

    request = ExperimentRequest(
        software_path=scan_path,
        language=args.language,
        website_url=args.url,
        sharp_website_detection=args.sharp_web,
        web_max_pages=args.web_max_pages,
        web_max_depth=args.web_max_depth,
        binary_path=args.binary_path,
        max_fuzz_iterations=args.fuzz_iterations,
    )
    result = orchestrator.run(request)
    payload = result.model_dump(mode="json")
    payload["policy"] = {"path": str((project_root / ".snsx" / "policy.json").resolve()), "loaded": bool(policy)}

    if args.auto_remediate and scan_path:
        root = str(Path(scan_path).expanduser().resolve())
        rem = orchestrator.remediate(
            result.experiment_id,
            RemediationRequest(
                grant_file_access=True,
                allow_write=True,
                allowed_root_paths=[root],
                dry_run=args.dry_run_remediation,
            ),
        )
        payload["remediation"] = rem.model_dump(mode="json")

    required_headers = policy.get("required_headers", []) if isinstance(policy, dict) else []
    if isinstance(required_headers, list):
        missing_required = _enforce_required_headers(payload, [str(h) for h in required_headers])
        if missing_required:
            payload["policy_header_failures"] = missing_required

    policy_linter_failures = []
    policy_test_failures = []
    if isinstance(policy.get("required_linters"), list):
        policy_linter_failures = _run_required_commands(project_root, policy["required_linters"], "linter")
    if isinstance(policy.get("required_tests"), list):
        policy_test_failures = _run_required_commands(project_root, policy["required_tests"], "test")
    if policy_linter_failures:
        payload["policy_linter_failures"] = policy_linter_failures
    if policy_test_failures:
        payload["policy_test_failures"] = policy_test_failures

    text = json.dumps(payload, indent=2)
    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        print(f"Wrote scan report to {out_path}")
    else:
        print(text)

    if payload.get("policy_header_failures") or policy_linter_failures or policy_test_failures:
        return 5
    return 0


def _run_audit(args: argparse.Namespace) -> int:
    path_value = _path_value(args.path)
    if not path_value:
        print("Path is required.")
        return 2
    target = Path(path_value).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}")
        return 2
    project_root = target if target.is_dir() else target.parent
    policy = _load_policy(project_root)
    profile, min_severity = _effective_security_settings(args, policy, project_root)
    custom_rules = policy.get("banned_apis", []) if isinstance(policy.get("banned_apis"), list) else []

    audit = SecurityAuditEngine().audit(target, profile=profile, extra_rules=custom_rules)
    filtered = _filter_findings(audit.findings, min_severity)
    linter_failures = _run_required_commands(project_root, policy.get("required_linters", []), "linter") \
        if isinstance(policy.get("required_linters"), list) else []
    test_failures = _run_required_commands(project_root, policy.get("required_tests", []), "test") \
        if isinstance(policy.get("required_tests"), list) else []
    payload = {
        "target": str(target),
        "files_scanned": audit.files_scanned,
        "language_profile_by_extension": dict(sorted(audit.language_counts.items())),
        "total_findings": len(audit.findings),
        "findings_after_threshold": len(filtered),
        "min_severity": min_severity,
        "profile": profile,
        "findings": [
            {
                **f.model_dump(mode="json"),
                "fix_plan": _fix_plan_for_finding(f),
            }
            for f in filtered
        ],
        "hardening_recommendations": _hardening_recommendations(filtered, audit.language_counts),
        "policy_linter_failures": linter_failures,
        "policy_test_failures": test_failures,
    }

    text = json.dumps(payload, indent=2)
    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        print(f"Wrote audit report to {out_path}")
    else:
        print(text)

    return 0 if (not filtered and not linter_failures and not test_failures) else 3


def _run_guard(args: argparse.Namespace) -> int:
    path_value = _path_value(args.path)
    if not path_value:
        print("Path is required.")
        return 2
    target = Path(path_value).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}")
        return 2
    project_root = target if target.is_dir() else target.parent
    policy = _load_policy(project_root)
    profile, min_severity = _effective_security_settings(args, policy, project_root)
    custom_rules = policy.get("banned_apis", []) if isinstance(policy.get("banned_apis"), list) else []

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("No command provided. Use: snsx guard-run --path . -- <command>")
        return 2

    audit = SecurityAuditEngine().audit(target, profile=profile, extra_rules=custom_rules)
    blocking = _filter_findings(audit.findings, min_severity)
    linter_failures = _run_required_commands(project_root, policy.get("required_linters", []), "linter") \
        if isinstance(policy.get("required_linters"), list) else []
    test_failures = _run_required_commands(project_root, policy.get("required_tests", []), "test") \
        if isinstance(policy.get("required_tests"), list) else []
    if blocking:
        print("Execution blocked by SNSX guard. Fix findings first.")
        print(_findings_to_text(blocking))
        return 4
    if linter_failures or test_failures:
        print("Execution blocked by SNSX policy checks.")
        for item in linter_failures + test_failures:
            print(f"  - {item}")
        return 4

    proc = subprocess.run(cmd, cwd=str(target.parent if target.is_file() else target))
    return proc.returncode


def _run_watch(args: argparse.Namespace) -> int:
    path_value = _path_value(args.path)
    if not path_value:
        print("Path is required.")
        return 2
    target = Path(path_value).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}")
        return 2
    project_root = target if target.is_dir() else target.parent
    policy = _load_policy(project_root)
    profile, min_severity = _effective_security_settings(args, policy, project_root)
    custom_rules = policy.get("banned_apis", []) if isinstance(policy.get("banned_apis"), list) else []

    print(
        f"Watching {target} every {args.interval}s "
        f"(profile={profile}, min-severity={min_severity})"
    )
    last_signature = ""
    try:
        while True:
            audit = SecurityAuditEngine().audit(target, profile=profile, extra_rules=custom_rules)
            filtered = _filter_findings(audit.findings, min_severity)
            signature = "\n".join(f"{f.severity}|{f.location}|{f.title}" for f in filtered)
            if signature != last_signature:
                last_signature = signature
                print("\n=== SNSX WATCH UPDATE ===")
                print(f"files_scanned={audit.files_scanned} findings={len(filtered)}")
                if filtered:
                    print(_findings_to_text(filtered))
                else:
                    print("No blocking findings.")
            time.sleep(max(args.interval, 1))
    except KeyboardInterrupt:
        print("Stopped watcher.")
        return 0


def _run_hook(args: argparse.Namespace) -> int:
    path_value = _path_value(args.path)
    if not path_value:
        print("Path is required.")
        return 2
    path = Path(path_value).expanduser().resolve()
    project_root = path if path.is_dir() else path.parent
    policy = _load_policy(project_root)
    profile, min_sev = _effective_security_settings(args, policy, project_root)
    snippet = f'''\n# SNSX Guard Hook\nfunction snsx_preexec_guard() {{\n  local cmd="$1"\n  if [[ "$cmd" == snsx* ]]; then\n    return\n  fi\n  snsx guard-run --path "{path}" --profile {profile} --min-severity {min_sev} -- echo >/dev/null 2>&1 || {{\n    echo "SNSX: blocking command due to security findings"\n    return 1\n  }}\n}}\nautoload -Uz add-zsh-hook\nadd-zsh-hook preexec snsx_preexec_guard\n'''
    print(snippet)
    return 0


def _run_init(args: argparse.Namespace) -> int:
    path_value = _path_value(args.path)
    if not path_value:
        print("Path is required.")
        return 2
    root = Path(path_value).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"Project directory not found: {root}")
        return 2

    cfg_dir = root / ".snsx"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = {"path": str(root), "profile": args.profile, "min_severity": args.min_severity}
    policy = {
        "path": str(root),
        "profile": args.profile,
        "min_severity": args.min_severity,
        "banned_apis": [],
        "required_headers": ["content-security-policy", "strict-transport-security"],
        "required_linters": [],
        "required_tests": [],
        "branch_gates": {"main": {"profile": "paranoid", "min_severity": "low"}},
        "environment_gates": {"production": {"profile": "paranoid", "min_severity": "low"}},
    }
    (cfg_dir / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    (cfg_dir / "policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")

    runner = cfg_dir / "run"
    runner.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"snsx guard-run --path \"{root}\" --profile {args.profile} --min-severity {args.min_severity} -- \"$@\"\n",
        encoding="utf-8",
    )
    os.chmod(runner, 0o755)

    print(f"SNSX guard initialized at {root} (profile={args.profile}, min_severity={args.min_severity})")
    print(f"Policy file created: {cfg_dir / 'policy.json'}")
    print(f"Use guarded runner: {runner}")
    return 0


def _run_uninstall(args: argparse.Namespace) -> int:
    path_value = _path_value(args.path)
    if not path_value:
        print("Path is required.")
        return 2
    root = Path(path_value).expanduser().resolve()
    cfg_dir = root / ".snsx"
    if not cfg_dir.exists():
        print(f"No SNSX config found in {root}")
        return 0

    for p in sorted(cfg_dir.rglob("*"), reverse=True):
        if p.is_file():
            p.unlink()
        elif p.is_dir():
            p.rmdir()
    cfg_dir.rmdir()
    print(f"Removed SNSX guard from {root}")
    return 0


def _interactive_mode() -> int:
    cwd = Path.cwd().resolve()
    installed_at = shutil.which("snsx") or "unknown"
    print("SNSX Interactive Security Console")
    print(f"- Installed binary: {installed_at}")
    print(f"- Active project directory: {cwd}")
    print("")
    print("Choose operation:")
    print("1) Audit current project")
    print("2) Guard-run command")
    print("3) Watch current project")
    print("4) Full scan (local path)")
    print("5) Website scan")
    print("6) Initialize strict project policy")
    print("7) Print zsh hook")
    print("8) Exit")
    choice = input("Enter choice [1-8]: ").strip()

    if choice == "1":
        profile = input("Profile [standard/strict/paranoid] (default: strict): ").strip() or "strict"
        min_sev = input("Min severity [info/low/medium/high/critical] (default: low): ").strip() or "low"
        ns = argparse.Namespace(path=[str(cwd)], profile=profile, min_severity=min_sev, output=None)
        return _run_audit(ns)
    if choice == "2":
        profile = input("Profile [standard/strict/paranoid] (default: strict): ").strip() or "strict"
        min_sev = input("Min severity [info/low/medium/high/critical] (default: low): ").strip() or "low"
        cmd = input("Command to run (example: npm run dev): ").strip()
        ns = argparse.Namespace(path=[str(cwd)], profile=profile, min_severity=min_sev, cmd=cmd.split(" "))
        return _run_guard(ns)
    if choice == "3":
        profile = input("Profile [standard/strict/paranoid] (default: strict): ").strip() or "strict"
        min_sev = input("Min severity [info/low/medium/high/critical] (default: low): ").strip() or "low"
        interval = int(input("Interval seconds (default: 5): ").strip() or "5")
        ns = argparse.Namespace(path=[str(cwd)], profile=profile, min_severity=min_sev, interval=interval)
        return _run_watch(ns)
    if choice == "4":
        profile = input("Website profile mode [sharp? y/n] (default: n): ").strip().lower()
        ns = argparse.Namespace(
            path=[str(cwd)],
            url=None,
            sharp_web=(profile == "y"),
            web_max_pages=20,
            web_max_depth=1,
            language="auto",
            binary_path=None,
            fuzz_iterations=50,
            auto_remediate=False,
            dry_run_remediation=False,
            output=None,
        )
        return _run_scan(ns)
    if choice == "5":
        url = input("Website URL: ").strip()
        pages = int(input("web_max_pages (default: 50): ").strip() or "50")
        depth = int(input("web_max_depth (default: 2): ").strip() or "2")
        ns = argparse.Namespace(
            path=None,
            url=url,
            sharp_web=True,
            web_max_pages=pages,
            web_max_depth=depth,
            language="unknown",
            binary_path=None,
            fuzz_iterations=1,
            auto_remediate=False,
            dry_run_remediation=False,
            output=None,
        )
        return _run_scan(ns)
    if choice == "6":
        profile = input("Profile [standard/strict/paranoid] (default: paranoid): ").strip() or "paranoid"
        min_sev = input("Min severity [info/low/medium/high/critical] (default: low): ").strip() or "low"
        ns = argparse.Namespace(path=[str(cwd)], profile=profile, min_severity=min_sev)
        return _run_init(ns)
    if choice == "7":
        profile = input("Profile [standard/strict/paranoid] (default: strict): ").strip() or "strict"
        min_sev = input("Min severity [info/low/medium/high/critical] (default: low): ").strip() or "low"
        ns = argparse.Namespace(path=[str(cwd)], profile=profile, min_severity=min_sev)
        return _run_hook(ns)
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return _interactive_mode()

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        if not _path_value(args.path) and not args.url:
            parser.error("Provide --path or --url.")
        return _run_scan(args)

    if args.command == "audit":
        return _run_audit(args)

    if args.command == "guard-run":
        return _run_guard(args)

    if args.command == "watch":
        return _run_watch(args)

    if args.command == "print-zsh-hook":
        return _run_hook(args)

    if args.command == "init":
        return _run_init(args)

    if args.command == "uninstall":
        return _run_uninstall(args)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
