from __future__ import annotations

import re
from pathlib import Path

from core.schemas import FileRemediation

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
}

CODE_EXTENSIONS = set(LANGUAGE_BY_EXT.keys())


class RemediationEngine:
    def collect_code_files(self, target_path: Path) -> list[Path]:
        if target_path.is_file() and target_path.suffix in CODE_EXTENSIONS:
            return [target_path]
        if target_path.is_dir():
            return sorted(
                p for p in target_path.rglob("*") if p.is_file() and p.suffix in CODE_EXTENSIONS and ".git" not in p.parts
            )
        return []

    def detect_languages(self, files: list[Path]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for file_path in files:
            lang = LANGUAGE_BY_EXT.get(file_path.suffix, "unknown")
            counts[lang] = counts.get(lang, 0) + 1
        return counts

    def remediate_files(self, files: list[Path], dry_run: bool = False) -> list[FileRemediation]:
        remediated: list[FileRemediation] = []
        for file_path in files:
            lang = LANGUAGE_BY_EXT.get(file_path.suffix, "unknown")
            if lang == "python":
                fix = self._remediate_python(file_path, dry_run=dry_run)
            elif lang in {"javascript", "typescript"}:
                fix = self._remediate_js_ts(file_path, dry_run=dry_run)
            else:
                continue

            if fix is not None:
                remediated.append(fix)

        return remediated

    def _remediate_python(self, file_path: Path, dry_run: bool) -> FileRemediation | None:
        src = file_path.read_text(encoding="utf-8", errors="ignore")
        updated = src
        changes: list[str] = []

        if re.search(r"\beval\(([^)\n]+)\)", updated):
            updated = re.sub(r"\beval\(([^)\n]+)\)", r"ast.literal_eval(\1)", updated)
            changes.append("Replaced eval() with ast.literal_eval()")

        if re.search(r"\bexec\(([^)\n]+)\)", updated):
            updated = re.sub(r"\bexec\(([^)\n]+)\)", r"ast.literal_eval(\1)", updated)
            changes.append("Replaced exec() with ast.literal_eval()")

        if re.search(r"\bpickle\.loads\(([^)\n]+)\)", updated):
            updated = re.sub(r"\bpickle\.loads\(([^)\n]+)\)", r"json.loads(\1)", updated)
            changes.append("Replaced pickle.loads() with json.loads()")

        if re.search(r"\bos\.system\(([^)\n]+)\)", updated):
            updated = re.sub(r"\bos\.system\(([^)\n]+)\)", r"subprocess.call(shlex.split(\1))", updated)
            changes.append("Replaced os.system() with subprocess.call(shlex.split())")

        if not changes:
            return None

        updated = self._ensure_python_imports(updated)
        backup_path = None

        if not dry_run:
            backup_path = f"{file_path}.bak"
            Path(backup_path).write_text(src, encoding="utf-8")
            file_path.write_text(updated, encoding="utf-8")

        return FileRemediation(
            file_path=str(file_path),
            language="python",
            changes_applied=changes,
            backup_path=backup_path,
        )

    def _remediate_js_ts(self, file_path: Path, dry_run: bool) -> FileRemediation | None:
        src = file_path.read_text(encoding="utf-8", errors="ignore")
        updated = src
        changes: list[str] = []

        if "eval(" in updated:
            updated = updated.replace("eval(", "JSON.parse(")
            changes.append("Replaced eval() with JSON.parse() placeholder")

        if not changes:
            return None

        backup_path = None
        if not dry_run:
            backup_path = f"{file_path}.bak"
            Path(backup_path).write_text(src, encoding="utf-8")
            file_path.write_text(updated, encoding="utf-8")

        return FileRemediation(
            file_path=str(file_path),
            language=LANGUAGE_BY_EXT.get(file_path.suffix, "unknown"),
            changes_applied=changes,
            backup_path=backup_path,
        )

    @staticmethod
    def _ensure_python_imports(source: str) -> str:
        needed: list[str] = []
        if "ast.literal_eval(" in source and not re.search(r"^\s*import\s+ast\b", source, flags=re.MULTILINE):
            needed.append("import ast")
        if "json.loads(" in source and not re.search(r"^\s*import\s+json\b", source, flags=re.MULTILINE):
            needed.append("import json")
        if "subprocess.call(" in source and not re.search(
            r"^\s*import\s+subprocess\b", source, flags=re.MULTILINE
        ):
            needed.append("import subprocess")
        if "shlex.split(" in source and not re.search(r"^\s*import\s+shlex\b", source, flags=re.MULTILINE):
            needed.append("import shlex")

        if not needed:
            return source

        lines = source.splitlines()
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        if len(lines) > insert_at and lines[insert_at].startswith('"""'):
            for i in range(insert_at + 1, len(lines)):
                if lines[i].startswith('"""'):
                    insert_at = i + 1
                    break

        for imp in reversed(needed):
            lines.insert(insert_at, imp)

        return "\n".join(lines) + ("\n" if source.endswith("\n") else "")
