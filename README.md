# Skills Sentry

Static scanner for agent skill bundles. Detects risky patterns (remote shell pipe, env secrets, cron persistence, etc.) before you install or publish a skill.

## Install

Python 3.10+. No extra dependencies.

```bash
git clone https://github.com/victorstack-ai/skills-sentry.git
cd skills-sentry
# optional: python -m venv .venv && source .venv/bin/activate
```

## Usage

Scan a folder or a zip bundle:

```bash
python skills_sentry.py scan ./some-skill-bundle
python skills_sentry.py scan ./skill.zip --json out/report.json
python skills_sentry.py scan ./bundle --fail-on high --max-score 60
```

- **`--json path`** — Write JSON report to file.
- **`--fail-on low|medium|high`** — Exit non-zero if any finding at or above this severity exists.
- **`--max-score N`** — Exit non-zero if risk score (0–100) exceeds N.

## Rules (examples)

| Rule ID            | Severity | Example pattern                          |
|--------------------|----------|------------------------------------------|
| REMOTE_SHELL_PIPE  | high     | `curl \| sh` / `wget \| bash`            |
| ENV_SECRETS        | high     | `.env`, `process.env`, `os.environ`      |
| CHMOD_EXEC         | medium   | `chmod +x`                               |
| EVAL_USAGE         | medium   | `eval(...)`                              |

See `skills_sentry.py` for the full list.

## CI

Run in GitHub Actions on PRs:

```yaml
- uses: actions/checkout@v4
- name: Run Skills Sentry
  run: python skills_sentry.py scan . --fail-on high --max-score 60 --json out/report.json
```

## License

MIT.
