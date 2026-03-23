# SNSX GitHub Install And Operations Manual

## 1) Goal

This manual explains end-to-end:
- how to download SNSX from GitHub
- where to place SNSX on your device
- where your target projects can live
- how to install SNSX from terminal in any code editor
- exact commands, their purpose, and strict-security workflow

SNSX is for authorized targets only.

## 2) Download From GitHub

```bash
git clone <YOUR_GITHUB_SNSX_REPO_URL> ~/tools/snsx
cd ~/tools/snsx
```

Recommended location:
- `~/tools/snsx` (or any stable tools directory)

Reason:
- keeps SNSX independent from scanned projects
- makes upgrades easier (`git pull`)

## 3) Install SNSX Tooling

```bash
cd ~/tools/snsx
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Verify:

```bash
snsx -h
```

## 4) Where To Keep Projects You Scan

Your project(s) can be anywhere, for example:
- `~/work/project-a`
- `~/work/project-b`
- `/Users/<you>/Documents/ClientApps/service-x`

SNSX scans by path, so you do not copy project code into SNSX.

## 5) Using SNSX In Any Code Editor Terminal

In VS Code / JetBrains / any terminal:

1. Activate SNSX environment:
```bash
source ~/tools/snsx/.venv/bin/activate
```

2. Run SNSX against the currently opened project path:
```bash
snsx audit --path /absolute/path/to/project --min-severity medium
```

## 6) Command Reference

### `snsx audit`
Purpose:
- fast static security audit
- exact file:line findings
- fix plans per finding

Command:
```bash
snsx audit --path /absolute/path/to/project --min-severity medium
```

Exit codes:
- `0` no findings at threshold
- `3` findings exist (useful for CI gating)

### `snsx guard-run`
Purpose:
- block program execution until findings are fixed

Command:
```bash
snsx guard-run --path /absolute/path/to/project --min-severity medium -- npm run dev
```

Behavior:
- if findings exist, command is blocked and detailed fix guidance is printed
- if clean, command runs

### `snsx watch`
Purpose:
- continuously monitor project for new blocking findings

Command:
```bash
snsx watch --path /absolute/path/to/project --interval 5 --min-severity medium
```

### `snsx scan`
Purpose:
- full experiment pipeline + detailed reports

Local code scan:
```bash
snsx scan --path /absolute/path/to/project --output ./reports/scan.json
```

Website scan:
```bash
snsx scan --url https://authorized-target.example --sharp-web --web-max-pages 50 --web-max-depth 2
```

### `snsx init`
Purpose:
- bind strict guard policy to one project directory

Command:
```bash
snsx init --path /absolute/path/to/project --min-severity medium
```

Creates:
- `.snsx/config.json`
- `.snsx/run`

Use guarded runner:
```bash
/absolute/path/to/project/.snsx/run npm run dev
```

### `snsx uninstall`
Purpose:
- remove project-bound guard config

```bash
snsx uninstall --path /absolute/path/to/project
```

### `snsx print-zsh-hook`
Purpose:
- generate zsh hook for preexec enforcement

```bash
snsx print-zsh-hook --path /absolute/path/to/project --min-severity medium
```

Append output to `~/.zshrc`.

## 7) Strict Security Workflow (Recommended)

1. Initialize project guard:
```bash
snsx init --path /absolute/path/to/project --min-severity medium
```

2. Start watcher in one terminal:
```bash
snsx watch --path /absolute/path/to/project --interval 5 --min-severity medium
```

3. Run app only through guard:
```bash
/absolute/path/to/project/.snsx/run <your_run_command>
```

4. Fix findings shown by SNSX.

5. Re-run audit until clean:
```bash
snsx audit --path /absolute/path/to/project --min-severity medium
```

## 8) CI/CD Gate Example

Add in CI pipeline:

```bash
snsx audit --path . --min-severity medium
```

Pipeline fails on non-zero exit if findings exist.

## 9) “Sticks To Directory” Behavior

SNSX can be made persistent per project via:
- `.snsx/config.json`
- `.snsx/run`
- shell hook or CI gate

OS-level undeletable installation is not supported (and should not be).
Explicit removal remains available via `snsx uninstall`.

## 10) Advanced Hardening Output

Audit output includes:
- exact finding details
- `fix_plan` with code examples
- verification instructions
- `hardening_recommendations` to improve overall security posture

## 11) Troubleshooting

### Paths with spaces
Both work:
```bash
snsx audit --path /Users/name/My Projects/service-a --min-severity medium
```
or
```bash
snsx audit --path "/Users/name/My Projects/service-a" --min-severity medium
```

### Tool not found
Activate environment:
```bash
source ~/tools/snsx/.venv/bin/activate
```

### Command blocked by guard
Run audit, fix all findings at threshold, retry:
```bash
snsx audit --path /project --min-severity medium
```

## 12) Strictness Profiles

SNSX supports three sensitivity levels:
- `standard`: baseline detection
- `strict`: stronger detection set (default)
- `paranoid`: most sensitive mode for aggressive review

Examples:

```bash
snsx audit --path /project --profile strict --min-severity low
```

```bash
snsx guard-run --path /project --profile paranoid --min-severity low -- npm run dev
```

## 13) Policy File (`.snsx/policy.json`)

Create `.snsx/policy.json` in project root to enforce strict custom policy.

Example:

```json
{
  "profile": "strict",
  "min_severity": "low",
  "banned_apis": [
    {
      "id": "ban_python_requests_verify_false",
      "pattern": "requests\\.(get|post|put|delete|request)\\([^\\n]*verify\\s*=\\s*False",
      "extensions": [".py"],
      "severity": "high",
      "type": "tls-verification-disabled",
      "title": "Custom policy: verify=False forbidden",
      "fix": "Remove verify=False and configure certificate trust correctly."
    }
  ],
  "required_headers": [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options"
  ],
  "required_linters": [
    { "name": "ruff", "cmd": "ruff check ." }
  ],
  "required_tests": [
    { "name": "pytest", "cmd": "pytest -q" }
  ],
  "branch_gates": {
    "main": { "profile": "paranoid", "min_severity": "low" }
  },
  "environment_gates": {
    "production": { "profile": "paranoid", "min_severity": "low" }
  }
}
```

Notes:
- `guard-run` and `watch` respect policy gates.
- `audit` includes policy-driven rules and failures.
- `scan` enforces `required_headers`, `required_linters`, and `required_tests` if configured.

## 14) Interactive SNSX Mode

Run:

```bash
snsx
```

SNSX automatically:
- detects installation path
- detects current project directory (working directory)
- displays a terminal choice menu for audit, guard-run, watch, scan, website scan, init, and hook generation.
