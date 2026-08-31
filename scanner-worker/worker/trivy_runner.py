from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

_SCAN_TIMEOUT_SECONDS = 300
_SCANNERS = "vuln,secret,misconfig"


class TrivyScanError(RuntimeError):
    """Trivy failed to run, timed out, or produced unparseable output."""


def run_trivy(target: Path) -> list[dict[str, Any]]:
    """Run Trivy against `target` and return its raw per-target Result objects.

    A single `trivy fs` invocation covers all three categories at once:
    SCA (vuln), secret scanning (secret), and IaC misconfiguration (misconfig).
    `target` must be a directory — Trivy's filesystem scanner does not
    produce results for a single file passed directly.
    """
    try:
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "trivy",
                "fs",
                "--scanners",
                _SCANNERS,
                "--format",
                "json",
                "--quiet",
                str(target),
            ],
            capture_output=True,
            timeout=_SCAN_TIMEOUT_SECONDS,
            check=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyScanError(f"trivy scan of {target} timed out after {_SCAN_TIMEOUT_SECONDS}s") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
        raise TrivyScanError(f"trivy scan of {target} failed: {stderr.strip()}") from exc

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise TrivyScanError(f"trivy produced invalid JSON for {target}") from exc

    # Unlike Semgrep's "results", Trivy omits "Results" entirely when there
    # is nothing to report — that's the normal shape of a clean scan, not
    # a broken one, so this falls back to [] rather than raising.
    return payload.get("Results", [])
