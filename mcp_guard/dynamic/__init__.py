"""Dynamic analysis. Implemented in Phase 3."""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from ..models import Finding, ServerInfo


def run_dynamic(info: ServerInfo, *, sandbox: str = "none",
                timeout: int = 120) -> Tuple[List[Finding], Dict[str, Any]]:
    raise NotImplementedError("dynamic engine not built yet (Phase 3)")
