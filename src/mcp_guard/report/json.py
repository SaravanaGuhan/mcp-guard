"""JSON report (versioned schema).

Absolute imports mean the stdlib ``json`` module is still reachable from here
despite the filename.
"""

from __future__ import annotations

import json as _json

from ..models import ScanResult


def render(result: ScanResult, indent: int = 2) -> str:
    return _json.dumps(result.as_dict(), indent=indent)
