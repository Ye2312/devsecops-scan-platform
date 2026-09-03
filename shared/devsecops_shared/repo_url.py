from __future__ import annotations

import re
from urllib.parse import urlparse

_REPO_PATH_RE = re.compile(r"^/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class InvalidRepoUrlError(ValueError):
    """The supplied URL isn't a well-formed https://github.com/<owner>/<repo> URL."""


def validate_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo) for a public GitHub URL, or raise InvalidRepoUrlError."""
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise InvalidRepoUrlError(f"unsupported scheme: {parsed.scheme!r}")

    if parsed.hostname != "github.com":
        raise InvalidRepoUrlError(f"unsupported host: {parsed.hostname!r}")

    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidRepoUrlError(f"malformed port in URL: {parsed.netloc!r}") from exc

    if port not in (None, 443):
        raise InvalidRepoUrlError(f"unsupported port: {port!r}")

    if parsed.username or parsed.password:
        raise InvalidRepoUrlError("credentials embedded in the URL are not allowed")

    match = _REPO_PATH_RE.match(parsed.path)
    if not match:
        raise InvalidRepoUrlError(f"URL does not look like a repo path: {parsed.path!r}")

    return match.group("owner"), match.group("repo")


def canonical_github_url(url: str) -> str:
    """Rebuild a normalized https://github.com/<owner>/<repo> URL from validated parts."""
    owner, repo = validate_github_url(url)
    return f"https://github.com/{owner}/{repo}"
