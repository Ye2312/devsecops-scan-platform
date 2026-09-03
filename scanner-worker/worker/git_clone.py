from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

from devsecops_shared.repo_url import InvalidRepoUrlError, validate_github_url

__all__ = ["CloneFailedError", "InvalidRepoUrlError", "clone_repository", "get_head_commit"]

_CLONE_TIMEOUT_SECONDS = 120


class CloneFailedError(RuntimeError):
    """`git clone` failed, was rejected, or timed out."""


@contextlib.contextmanager
def clone_repository(url: str) -> Iterator[Path]:
    """Shallow-clone a GitHub repo into a fresh temporary directory.

    Yields the checkout path. The directory is removed when the context
    exits, whether or not the block raised.
    """
    owner, repo = validate_github_url(url)
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
        except OSError as exc:
            raise CloneFailedError(f"could not run git: {exc}") from exc

        checkout = Path(workdir)
        for ignore_file in checkout.rglob(".semgrepignore"):
            ignore_file.unlink(missing_ok=True)

        yield checkout
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def get_head_commit(repo_path: Path) -> str | None:
    """Return the checked-out commit SHA, or None if the repository has no commits."""
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            timeout=10,
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise CloneFailedError(f"could not read HEAD of {repo_path}: {exc}") from exc
    return result.stdout.strip()
