from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections import Counter
from pathlib import Path

from worker.git_clone import CloneFailedError, InvalidRepoUrlError, clone_repository, get_head_commit
from worker.normalize import Finding, normalize_all
from worker.semgrep_runner import SemgrepScanError, run_semgrep
from worker.trivy_runner import TrivyScanError, run_trivy

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _repo_path(value: str) -> Path:
    if not value.strip():
        raise argparse.ArgumentTypeError("path must not be empty")
    return Path(value)


def scan_path(target: Path) -> list[Finding]:
    findings = normalize_all(run_semgrep(target), run_trivy(target))
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id, f.file_path or ""),
    )


def _render_json(findings: list[Finding], include_raw: bool) -> str:
    payload = []
    for finding in findings:
        item = dataclasses.asdict(finding)
        if not include_raw:
            item.pop("raw")
        payload.append(item)
    return json.dumps(payload, indent=2)


def _render_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."

    by_severity = Counter(f.severity for f in findings)
    by_category = Counter(f.category for f in findings)

    severities = ", ".join(f"{s}={by_severity[s]}" for s in _SEVERITY_ORDER if by_severity[s])
    categories = ", ".join(f"{c}={n}" for c, n in sorted(by_category.items()))

    lines = [f"{len(findings)} findings", "", f"By severity: {severities}", f"By category: {categories}", ""]

    for finding in findings:
        location = finding.file_path or "-"
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        lines.append(f"  [{finding.severity:<8}] {finding.category:<6} {finding.rule_id}")
        lines.append(f"             {location}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="worker.cli", description="Scan a repository for security findings."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a local directory or a GitHub repository.")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("path", nargs="?", type=_repo_path, help="Local directory to scan.")
    source.add_argument("--url", help="GitHub repository URL to clone and scan.")
    scan.add_argument("--format", choices=("json", "summary"), default="summary")
    scan.add_argument("--include-raw", action="store_true", help="Include raw tool output in JSON.")

    args = parser.parse_args(argv)

    if args.url is not None and not args.url.strip():
        scan.error("--url must not be empty")

    try:
        if args.url is not None:
            with clone_repository(args.url) as repo_path:
                commit = get_head_commit(repo_path)
                print(f"Scanning {args.url} at {commit or 'no commits'}", file=sys.stderr)
                findings = scan_path(repo_path)
        else:
            target = args.path.resolve()
            if not target.is_dir():
                print(f"error: {target} is not a directory", file=sys.stderr)
                return 2
            findings = scan_path(target)
    except (InvalidRepoUrlError, CloneFailedError, SemgrepScanError, TrivyScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(_render_json(findings, args.include_raw))
    else:
        print(_render_summary(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
