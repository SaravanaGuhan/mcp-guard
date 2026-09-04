"""OSV.dev advisory lookup.

Uses the public querybatch endpoint with package URLs, batched, with retry and
a disk cache keyed by purl. Severity is taken as OSV published it -- this module
never recomputes or invents a score.

Rate limit: OSV documents no hard public quota, but asks for reasonable use.
This client sends at most ``BATCH`` purls per request, sleeps ``PAUSE`` seconds
between batches, and retries with exponential backoff on 429/5xx.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import requests

API = "https://api.osv.dev/v1/querybatch"
API_VULN = "https://api.osv.dev/v1/vulns/"
BATCH = 100
PAUSE = 0.2
VULN_WORKERS = 8
TIMEOUT = 30
RETRIES = 3


def cache_dir() -> str:
    base = os.environ.get("MCPGUARD_CACHE") or os.path.join(
        os.path.expanduser("~"), ".cache", "mcp-guard", "osv")
    os.makedirs(base, exist_ok=True)
    return base


def _cache_path(key: str) -> str:
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    return os.path.join(cache_dir(), f"{h}.json")


_CACHE_STATS = {"hits": 0, "misses": 0}


def cache_stats() -> Dict[str, int]:
    return dict(_CACHE_STATS)


def cache_get(key: str) -> Optional[Any]:
    p = _cache_path(key)
    try:
        with open(p, encoding="utf-8") as fh:
            value = json.load(fh)
        if key.startswith("purl:"):
            _CACHE_STATS["hits"] += 1
        return value
    except Exception:
        if key.startswith("purl:"):
            _CACHE_STATS["misses"] += 1
        return None


def cache_put(key: str, value: Any) -> None:
    try:
        with open(_cache_path(key), "w", encoding="utf-8") as fh:
            json.dump(value, fh)
    except Exception:
        pass


@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    affected_range: str
    severity: Optional[str]        # as published by OSV, or None
    cvss_vector: Optional[str]     # as published by OSV, or None
    aliases: List[str]
    url: str


class OSVError(RuntimeError):
    pass


def _post(payload: Dict[str, Any]) -> Dict[str, Any]:
    delay = 1.0
    last: Optional[Exception] = None
    for attempt in range(RETRIES):
        try:
            r = requests.post(API, json=payload, timeout=TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 500, 502, 503, 504):
                last = OSVError(f"OSV HTTP {r.status_code}")
                time.sleep(delay)
                delay *= 2
                continue
            raise OSVError(f"OSV HTTP {r.status_code}: {r.text[:200]}")
        except requests.RequestException as exc:
            last = exc
            time.sleep(delay)
            delay *= 2
    raise OSVError(f"OSV request failed after {RETRIES} attempts: {last}")


def _get_vuln(vuln_id: str) -> Optional[Dict[str, Any]]:
    cached = cache_get("vuln:" + vuln_id)
    if cached is not None:
        return cached
    delay = 1.0
    for _ in range(RETRIES):
        try:
            r = requests.get(API_VULN + vuln_id, timeout=TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                cache_put("vuln:" + vuln_id, data)
                return data
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(delay)
                delay *= 2
                continue
            return None
        except requests.RequestException:
            time.sleep(delay)
            delay *= 2
    return None


def _vparts(v: str) -> tuple:
    """Loose version tuple for range comparison. Numeric parts compare
    numerically; anything else compares as a string, which is enough to place a
    version inside a published range."""
    out = []
    for part in re.split(r"[.\-+]", (v or "").lstrip("vV")):
        if part.isdigit():
            out.append((0, int(part), ""))
        elif part:
            out.append((1, 0, part))
    return tuple(out)


def _in_range(version: str, introduced: str, fixed: Optional[str]) -> bool:
    v = _vparts(version)
    if introduced and introduced != "0" and v < _vparts(introduced):
        return False
    if fixed and v >= _vparts(fixed):
        return False
    return True


def _affected_range(vuln: Dict[str, Any], package_name: str,
                    installed: str = "") -> str:
    """The range that actually contains ``installed``.

    OSV returns a vulnerability when ANY of its affected entries matches, and an
    advisory often carries several ranges (a 0.x line and a 1.x line, say).
    Reporting the first one produced evidence that contradicted itself: an
    installed 0.21.0 shown against a range of >=1.0.0 <1.16.0. Pick the range
    the installed version falls into; only if none can be matched do we fall
    back to listing them, and we say so.
    """
    all_parts: List[str] = []
    for aff in vuln.get("affected") or []:
        pkg = (aff.get("package") or {}).get("name", "")
        if pkg and package_name and pkg.lower() != package_name.lower():
            continue

        for rng in aff.get("ranges") or []:
            events = rng.get("events") or []
            intro = ""
            for e in events:
                if "introduced" in e:
                    intro = e["introduced"]
                if "fixed" in e:
                    fixed = e["fixed"]
                    text = f">={intro or '0'} <{fixed}"
                    if installed and _in_range(installed, intro, fixed):
                        return text
                    all_parts.append(text)
                    intro = ""
            if intro:
                text = f">={intro}"
                if installed and _in_range(installed, intro, None):
                    return text
                all_parts.append(text)

        versions = aff.get("versions") or []
        if installed and installed in versions:
            return f"exact version {installed} is listed as affected"
        if versions:
            all_parts.append("versions: " + ", ".join(versions[:5])
                             + (" ..." if len(versions) > 5 else ""))

    if all_parts:
        return ("OSV matched this version; published ranges: "
                + "; ".join(dict.fromkeys(all_parts))[:300])
    return "see advisory"


def _severity(vuln: Dict[str, Any]) -> tuple:
    """(qualitative, cvss_vector) exactly as OSV publishes them."""
    vec = None
    for sev in vuln.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS"):
            vec = sev.get("score")
            break
    db = vuln.get("database_specific") or {}
    qual = db.get("severity")
    if isinstance(qual, str):
        qual = qual.upper()
    return qual, vec


def query(purls: Sequence[str]) -> Dict[str, List[Advisory]]:
    """Map purl -> advisories. Cached per purl."""
    out: Dict[str, List[Advisory]] = {}
    todo: List[str] = []

    for purl in purls:
        hit = cache_get("purl:" + purl)
        if hit is not None:
            out[purl] = [Advisory(**a) for a in hit]
        else:
            todo.append(purl)

    for i in range(0, len(todo), BATCH):
        chunk = todo[i:i + BATCH]
        payload = {"queries": [{"package": {"purl": p}} for p in chunk]}
        data = _post(payload)
        results = data.get("results") or []
        # Fetch the full record for every advisory in this batch concurrently.
        # These are independent GETs against the same host and were the
        # dominant cost: a 551-package repo issued ~90 of them one at a time.
        wanted = []
        for res in results:
            for stub in (res.get("vulns") or []):
                vid = stub.get("id")
                if vid:
                    wanted.append(vid)
        full_by_id: Dict[str, Any] = {}
        if wanted:
            uniq = list(dict.fromkeys(wanted))
            with ThreadPoolExecutor(max_workers=min(VULN_WORKERS, len(uniq))) as ex:
                for vid, data in zip(uniq, ex.map(_get_vuln, uniq)):
                    if data is not None:
                        full_by_id[vid] = data

        for purl, res in zip(chunk, results):
            advisories: List[Advisory] = []
            for stub in (res.get("vulns") or []):
                vid = stub.get("id")
                if not vid:
                    continue
                full = full_by_id.get(vid) or stub
                qual, vec = _severity(full)
                base = purl.split("/", 1)[-1]
                name, _, version = base.rpartition("@")
                advisories.append(Advisory(
                    id=vid,
                    summary=(full.get("summary")
                             or (full.get("details") or "")[:200]
                             or "no summary published"),
                    affected_range=_affected_range(full, name, version),
                    severity=qual,
                    cvss_vector=vec,
                    aliases=list(full.get("aliases") or []),
                    url=f"https://osv.dev/vulnerability/{vid}",
                ))
            out[purl] = advisories
            cache_put("purl:" + purl, [a.__dict__ for a in advisories])
        if i + BATCH < len(todo):
            time.sleep(PAUSE)

    return out
