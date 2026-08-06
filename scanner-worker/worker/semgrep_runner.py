from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SCAN_TIMEOUT_SECONDS = 300


class SemgrepScanError(RuntimeError):
    """Semgrep failed to run, timed out, or produced unparseable output."""


def run_semgrep(target: Path) -> list[dict[str, Any]]:
    """Run Semgrep against `target` and return its raw finding objects.

    Uses --config=auto, which pulls community rulesets from Semgrep's
    registry based on languages detected in `target`. Per-file parse
    errors Semgrep reports are logged and skipped rather than raising —
    a single unparseable file in an otherwise-large repo shouldn't abort
    the whole scan.
    """
    try:
        result = subprocess.run(  # noqa: S603
            ["semgrep", "scan", "--config=auto", "--json", "--quiet", str(target)],  # noqa: S607
            capture_output=True,
            timeout=_SCAN_TIMEOUT_SECONDS,
            check=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepScanError(f"semgrep scan of {target} timed out after {_SCAN_TIMEOUT_SECONDS}s") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
        raise SemgrepScanError(f"semgrep scan of {target} failed: {stderr.strip()}") from exc

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepScanError(f"semgrep produced invalid JSON for {target}") from exc

    for error in payload.get("errors", []):
        log.warning("semgrep reported a scan error for %s: %s", target, error.get("message", error))

    return payload["results"]
