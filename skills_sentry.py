#!/usr/bin/env python3
"""Static scanner for agent skill bundles. Detects risky patterns (remote shell pipe, env secrets, etc.)."""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


@dataclass
class Finding:
    severity: str  # low, medium, high
    rule_id: str
    message: str
    file: str
    line: Optional[int] = None
    excerpt: Optional[str] = None


RULES: List[Tuple[str, str, str, re.Pattern]] = [
    # rule_id, severity, message, regex
    (
        "REMOTE_SHELL_PIPE",
        "high",
        "Remote script piped to a shell is a classic supply-chain footgun.",
        re.compile(r"\b(curl|wget)\b.*\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
    ),
    (
        "POWERSHELL_IWR_EXEC",
        "high",
        "PowerShell download-and-exec pattern detected.",
        re.compile(r"\b(iwr|Invoke-WebRequest)\b.*\|\s*(iex|Invoke-Expression)\b", re.IGNORECASE),
    ),
    (
        "BASE64_DECODE_EXEC",
        "high",
        "Base64 decode combined with execution often indicates obfuscation.",
        re.compile(r"(base64\s+-d|frombase64|atob)\b.*(sh|bash|powershell|python|node|eval)", re.IGNORECASE),
    ),
    (
        "EVAL_USAGE",
        "medium",
        "Eval usage is risky and commonly abused.",
        re.compile(r"\b(eval|Function)\s*\(", re.IGNORECASE),
    ),
    (
        "CHMOD_EXEC",
        "medium",
        "chmod +x during install is not always bad, but it increases risk.",
        re.compile(r"\bchmod\s+\+x\b", re.IGNORECASE),
    ),
    (
        "CRON_PERSISTENCE",
        "high",
        "Cron or scheduled task persistence hints at unwanted background behavior.",
        re.compile(r"\b(crontab|cron\.d|launchctl|LaunchAgents|schtasks)\b", re.IGNORECASE),
    ),
    (
        "SSH_KEY_TOUCH",
        "high",
        "Touching SSH keys or config is a red flag in a skill bundle.",
        re.compile(r"(\.ssh/|id_rsa|known_hosts|ssh_config)", re.IGNORECASE),
    ),
    (
        "ENV_SECRETS",
        "high",
        "Accessing env files or secrets is high risk in marketplace code.",
        re.compile(r"(\.env\b|dotenv|process\.env|os\.environ)", re.IGNORECASE),
    ),
    (
        "WALLET_KEYWORDS",
        "high",
        "Crypto wallet keywords detected. Treat as sensitive.",
        re.compile(r"\b(seed phrase|mnemonic|private key|wallet|metamask)\b", re.IGNORECASE),
    ),
    (
        "OBFUSCATED_BLOB",
        "medium",
        "Large encoded blobs often hide payloads.",
        re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"),
    ),
]

TEXT_EXTS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".py", ".js", ".ts", ".tsx", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".rb", ".go", ".java", ".php",
}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}


def iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def is_text_candidate(p: Path) -> bool:
    if p.suffix.lower() in TEXT_EXTS:
        return True
    try:
        return p.stat().st_size <= 512_000
    except OSError:
        return False


def read_lines(p: Path) -> List[str]:
    try:
        data = p.read_bytes()
    except OSError:
        return []
    if b"\x00" in data[:4096]:
        return []
    try:
        return data.decode("utf-8", errors="replace").splitlines()
    except Exception:
        return []


def scan_text_file(p: Path, root: Path) -> List[Finding]:
    rel = str(p.relative_to(root))
    lines = read_lines(p)
    findings: List[Finding] = []
    for idx, line in enumerate(lines, start=1):
        for rule_id, severity, message, pattern in RULES:
            if pattern.search(line):
                findings.append(
                    Finding(
                        severity=severity,
                        rule_id=rule_id,
                        message=message,
                        file=rel,
                        line=idx,
                        excerpt=line.strip()[:240],
                    )
                )
    return findings


def score(findings: List[Finding]) -> int:
    weights = {"low": 5, "medium": 15, "high": 30}
    raw = sum(weights.get(f.severity, 0) for f in findings)
    return min(100, raw)


def summarize(findings: List[Finding]) -> dict:
    by_sev = {"high": [], "medium": [], "low": []}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    return {
        "counts": {k: len(v) for k, v in by_sev.items()},
        "findings": {
            k: [
                {"rule_id": x.rule_id, "message": x.message, "file": x.file, "line": x.line, "excerpt": x.excerpt}
                for x in v
            ]
            for k, v in by_sev.items()
        },
    }


def unpack_if_zip(path: Path) -> Path:
    if path.is_dir():
        return path
    if path.suffix.lower() != ".zip":
        raise ValueError("Input must be a folder or a .zip file.")
    tmp = Path(tempfile.mkdtemp(prefix="skills_sentry_"))
    with zipfile.ZipFile(path, "r") as z:
        z.extractall(tmp)
    return tmp


def scan_bundle(input_path: Path) -> Tuple[int, List[Finding], Path]:
    root = unpack_if_zip(input_path)
    findings: List[Finding] = []
    for f in iter_files(root):
        if not is_text_candidate(f):
            continue
        findings.extend(scan_text_file(f, root))
    return score(findings), findings, root


def fail_decision(findings: List[Finding], risk: int, fail_on: Optional[str], max_score: Optional[int]) -> bool:
    if max_score is not None and risk > max_score:
        return True
    if not fail_on:
        return False
    sev_rank = {"low": 1, "medium": 2, "high": 3}
    min_rank = sev_rank.get(fail_on.lower(), 3)
    for f in findings:
        if sev_rank.get(f.severity, 0) >= min_rank:
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(prog="skills_sentry", description="Static scanner for agent skill bundles.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="Scan a folder or zip bundle and print a report.")
    scan.add_argument("path", help="Path to a skill folder or .zip bundle.")
    scan.add_argument("--json", dest="json_path", help="Write JSON report to this path.")
    scan.add_argument("--fail-on", choices=["low", "medium", "high"], help="Exit non-zero if findings at or above this severity exist.")
    scan.add_argument("--max-score", type=int, help="Exit non-zero if risk score exceeds this value (0-100).")
    args = ap.parse_args()
    input_path = Path(args.path).expanduser().resolve()
    try:
        risk, findings, root = scan_bundle(input_path)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    report = {"risk_score": risk, "root": str(root), **summarize(findings)}
    print(f"Risk score: {risk}/100")
    print(f"High: {report['counts']['high']}  Medium: {report['counts']['medium']}  Low: {report['counts']['low']}")
    if report["counts"]["high"] or report["counts"]["medium"]:
        print("\nTop findings:")
        shown = 0
        for sev in ["high", "medium", "low"]:
            for f in report["findings"][sev]:
                print(f"- [{sev.upper()}] {f['rule_id']} in {f['file']}:{f['line']}  {f['excerpt']}")
                shown += 1
                if shown >= 12:
                    break
            if shown >= 12:
                break
    json_path = getattr(args, "json_path", None)
    if json_path:
        out = Path(json_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote JSON report: {out}")
    should_fail = fail_decision(findings, risk, getattr(args, "fail_on", None), getattr(args, "max_score", None))
    return 1 if should_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
