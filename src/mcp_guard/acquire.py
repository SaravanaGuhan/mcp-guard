"""Target acquisition.

Ported from the working GitHub-ZIP download in the original scanner. Two
additions the original lacked: local paths are first-class (so the test corpus
does not need a network), and the resolved commit sha is recorded so a report
can name exactly what was scanned.

Acquisition never executes anything from the target.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import requests

DEFAULT_BRANCHES = ("main", "master", "develop")
_TIMEOUT = 60


class AcquireError(RuntimeError):
    pass


@dataclass
class Acquired:
    root: str
    origin: str
    commit: Optional[str] = None
    temp_dirs: List[str] = None  # type: ignore[assignment]

    def cleanup(self) -> None:
        for d in self.temp_dirs or []:
            shutil.rmtree(d, ignore_errors=True)


def _is_local(target: str) -> bool:
    if target.startswith(("http://", "https://", "git@")):
        return False
    return os.path.exists(target)


def _local_commit(path: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", path, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except Exception:
        pass
    return None


def _owner_repo(url: str) -> tuple[str, str]:
    p = urlparse(url if url.startswith("http") else f"https://{url}")
    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 2:
        raise AcquireError(f"cannot derive owner/repo from {url!r}")
    return parts[0], parts[1].removesuffix(".git")


def acquire(target: str, branches: tuple = DEFAULT_BRANCHES) -> Acquired:
    """Return an Acquired pointing at a local directory holding the target."""
    if _is_local(target):
        root = os.path.abspath(target)
        if not os.path.isdir(root):
            raise AcquireError(f"{target!r} is not a directory")
        return Acquired(root=root, origin=target,
                        commit=_local_commit(root), temp_dirs=[])

    if "github.com" not in target:
        raise AcquireError(
            f"only GitHub URLs and local paths are supported, got {target!r}"
        )

    owner, repo = _owner_repo(target)
    tmp = tempfile.mkdtemp(prefix="mcpguard_")
    errors = []
    for branch in branches:
        url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
        try:
            r = requests.get(url, timeout=_TIMEOUT)
            if r.status_code != 200:
                errors.append(f"{branch}: HTTP {r.status_code}")
                continue
            with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
                zf.extractall(tmp)
            entries = [os.path.join(tmp, e) for e in os.listdir(tmp)]
            dirs = [e for e in entries if os.path.isdir(e)]
            if not dirs:
                errors.append(f"{branch}: archive contained no directory")
                continue
            return Acquired(root=dirs[0], origin=target,
                            commit=f"refs/heads/{branch}", temp_dirs=[tmp])
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{branch}: {exc}")

    shutil.rmtree(tmp, ignore_errors=True)
    raise AcquireError(
        f"could not download {owner}/{repo} from any branch ({'; '.join(errors)})"
    )
