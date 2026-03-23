from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".kt": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
}


@dataclass(slots=True)
class LanguageProfileResult:
    summary: str
    data: dict


class LanguageDetectionEngine:
    def analyze(self, target: Path) -> LanguageProfileResult:
        files: list[Path]
        if target.is_file():
            files = [target]
        else:
            files = [p for p in target.rglob("*") if p.is_file() and ".git" not in p.parts]

        counts: dict[str, int] = {}
        known = 0
        for file_path in files:
            lang = LANGUAGE_BY_EXT.get(file_path.suffix.lower(), "unknown")
            counts[lang] = counts.get(lang, 0) + 1
            if lang != "unknown":
                known += 1

        summary = f"Language profiling scanned {len(files)} files across {len(counts)} language buckets."
        return LanguageProfileResult(
            summary=summary,
            data={
                "files_scanned": len(files),
                "known_language_files": known,
                "languages": dict(sorted(counts.items(), key=lambda x: (-x[1], x[0]))),
            },
        )
