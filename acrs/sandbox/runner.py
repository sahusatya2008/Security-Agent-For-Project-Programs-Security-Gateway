from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class SandboxResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


class SandboxRunner:
    def run(self, command: str, timeout: int = 10) -> SandboxResult:
        args = shlex.split(command)
        if not args:
            raise ValueError("Command must not be empty.")
        proc = subprocess.run(args, shell=False, capture_output=True, text=True, timeout=timeout)
        return SandboxResult(
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
