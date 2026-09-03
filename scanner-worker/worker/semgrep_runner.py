from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SCAN_TIMEOUT_SECONDS = 300


class SemgrepScanError(RuntimeError):
    """Semgrep failed to run, timed out, or produced unparseable output."""


def _kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=10)


def run_semgrep(target: Path) -> list[dict[str, Any]]:
    """Run Semgrep against `target` and return its raw finding objects.

    Uses --config=auto, which pulls community rulesets from Semgrep's
    registry based on languages detected in `target`. Per-file parse
    errors Semgrep reports are logged and skipped rather than raising —
    a single unparseable file in an otherwise-large repo shouldn't abort
    the whole scan.

    Runs with `target` as the working directory so reported paths are
    relative to the scanned tree, matching Trivy's output. The child is
    started in its own process group so a timeout can reap the whole tree:
    the semgrep CLI delegates analysis to a semgrep-core grandchild that
    would otherwise survive a kill aimed at the direct child alone.
    """
    try:
        proc = subprocess.Popen(  # noqa: S603
            ["semgrep", "scan", "--config=auto", "--json", "."],  # noqa: S607
            cwd=target,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise SemgrepScanError(f"could not run semgrep: {exc}") from exc

    try:
        stdout, stderr = proc.communicate(timeout=_SCAN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(proc)
        raise SemgrepScanError(f"semgrep scan of {target} timed out after {_SCAN_TIMEOUT_SECONDS}s") from exc

    if proc.returncode != 0:
        message = stderr.decode(errors="replace").strip()
        raise SemgrepScanError(
            f"semgrep scan of {target} failed (exit {proc.returncode}): {message[-2000:] or '<no stderr>'}"
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepScanError(f"semgrep produced invalid JSON for {target}") from exc

    for error in payload.get("errors", []):
        log.warning("semgrep reported a scan error for %s: %s", target, error.get("message", error))

    return payload["results"]
