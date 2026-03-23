# SNSX Installation And Usage Guide

## 1) What This Guide Covers

This guide explains how to install and use SNSX on any project directory (single-language or polyglot), including:
- terminal setup
- scanning local file/folder projects
- scanning authorized websites
- strict run-blocking guard mode
- continuous watch mode
- CI integration

Use only for software and domains you are explicitly authorized to test.

## 2) Install SNSX (Terminal)

From the SNSX repository root:

```bash
cd /absolute/path/to/acrs
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Verify:

```bash
snsx -h
```

## 3) Use SNSX On Another Project

You can scan any project path directly from terminal.

Example:

```bash
snsx audit --path /absolute/path/to/your-project --min-severity medium
```

Paths with spaces are supported:

```bash
snsx audit --path /Users/name/My Projects/service-api --min-severity medium
```

## 4) Language Coverage Model

SNSX automatically inspects common source/config files and reports exact `file:line`.

Current extensions include:
- `.py`, `.js`, `.ts`, `.tsx`, `.jsx`
- `.go`, `.java`, `.php`, `.rb`
- `.env`, `.yaml`, `.yml`, `.json`, `.toml`

For full experiments (`snsx scan`), SNSX also generates language profile summaries in reports.

## 5) Core Commands

### 5.1 Fast Security Audit

```bash
snsx audit --path /absolute/path/to/project --min-severity medium
```

- returns JSON output
- non-zero exit when findings meet threshold
- includes exact location and fix guidance in evidence

### 5.2 Full Experiment Scan

```bash
snsx scan --path /absolute/path/to/project --output ./reports/scan.json
```

Includes static analysis, language profiling, reporting pipeline, and artifacts.

### 5.3 Website Scan (Authorized Targets)

```bash
snsx scan \
  --url https://authorized-target.example \
  --sharp-web \
  --web-max-pages 50 \
  --web-max-depth 2
```

For website-only runs, no local path is required.

### 5.4 Guarded Execution (Block Until Fixed)

```bash
snsx guard-run --path /absolute/path/to/project --min-severity medium -- npm run dev
```

Behavior:
- SNSX audits project first
- if findings >= threshold, command is blocked
- if no blocking findings, command runs

### 5.5 Continuous Watch

```bash
snsx watch --path /absolute/path/to/project --interval 5 --min-severity medium
```

Use this to monitor changing codebases during active development.

## 6) Bind Guard To A Project (Sticky Directory Policy)

Initialize project guard:

```bash
snsx init --path /absolute/path/to/project --min-severity medium
```

This creates:
- `.snsx/config.json`
- `.snsx/run`

Run commands through project guard wrapper:

```bash
/absolute/path/to/project/.snsx/run npm run dev
```

Remove project binding:

```bash
snsx uninstall --path /absolute/path/to/project
```

## 7) Optional Shell Hook (zsh)

Generate hook:

```bash
snsx print-zsh-hook --path /absolute/path/to/project --min-severity medium
```

Append output to `~/.zshrc` to enforce preexec checks in that shell profile.

## 8) Report Outputs

Full scans generate:
- `reports/<experiment_id>/report.json`
- `reports/<experiment_id>/report.md`

These include:
- findings
- severity summaries
- language profile
- website profile (when URL scan is used)
- remediation guidance

## 9) CI Integration Examples

### GitHub Actions Step

```bash
snsx audit --path . --min-severity medium
```

If findings exist at/above threshold, job fails (non-zero exit), which blocks merge/deploy.

### Pre-run Script

Wrap service startup:

```bash
snsx guard-run --path . --min-severity medium -- ./start.sh
```

## 10) Operational Notes

- SNSX cannot be made truly undeletable at OS level.
- For persistence, install in team bootstrap scripts and CI gates.
- Keep thresholds practical:
  - local dev: `high`
  - release branches/CI: `medium` or `high` based on policy

## 11) Troubleshooting

### `unrecognized arguments` for path with spaces
- Use `--path` exactly once; latest SNSX supports multi-word path values.

### Command blocked unexpectedly
- Run:
  - `snsx audit --path /project --min-severity <threshold>`
- Fix listed file/line findings, then rerun.

### Website scan returns reachability error
- Confirm target URL is reachable from your network.
- Confirm scanning is authorized and not blocked by network policy.
