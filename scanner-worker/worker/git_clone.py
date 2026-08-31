from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

_REPO_PATH_RE = re.compile(r"^/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$")
_CLONE_TIMEOUT_SECONDS = 120


class InvalidRepoUrlError(ValueError):
    """The supplied URL isn't a well-formed https://github.com/<owner>/<repo> URL."""


class CloneFailedError(RuntimeError):
    """`git clone` failed, was rejected, or timed out."""


def _validate_github_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise InvalidRepoUrlError(f"unsupported scheme: {parsed.scheme!r}")

    if parsed.hostname != "github.com":
        raise InvalidRepoUrlError(f"unsupported host: {parsed.hostname!r}")

    if parsed.port not in (None, 443):
        raise InvalidRepoUrlError(f"unsupported port: {parsed.port!r}")

    if parsed.username or parsed.password:
        raise InvalidRepoUrlError("credentials embedded in the URL are not allowed")

    match = _REPO_PATH_RE.match(parsed.path)
    if not match:
        raise InvalidRepoUrlError(f"URL does not look like a repo path: {parsed.path!r}")

    return match.group("owner"), match.group("repo")


@contextlib.contextmanager
def clone_repository(url: str) -> Iterator[Path]:
    """Shallow-clone a GitHub repo into a fresh temporary directory.

    Yields the checkout path. The directory is removed when the context
    exits, whether or not the block raised.
    """
    owner, repo = _validate_github_url(url)
    clone_url = f"https://github.com/{owner}/{repo}.git"

    workdir = tempfile.mkdtemp(prefix="scan-")
    try:
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
        }
        try:
            subprocess.run(  # noqa: S603
                ["git", "clone", "--depth", "1", clone_url, workdir],  # noqa: S607
                env=env,
                capture_output=True,
                timeout=_CLONE_TIMEOUT_SECONDS,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise CloneFailedError(f"clone of {clone_url} timed out after {_CLONE_TIMEOUT_SECONDS}s") from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
            raise CloneFailedError(f"git clone failed for {clone_url}: {stderr.strip()}") from exc

        yield Path(workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def get_head_commit(repo_path: Path) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        timeout=10,
        check=True,
        text=True,
    )
    return result.stdout.strip()
