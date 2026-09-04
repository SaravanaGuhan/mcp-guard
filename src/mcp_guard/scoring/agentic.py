"""Deciding which AIVSS factors a scan actually observed.

This module is where the observability rule is enforced. It answers one
question per factor: did this scan see it, and from what?

What a repository scanner can see:

  Tools (External Tool Control Surface)
      Yes, when the dynamic stage ran. tools/list returns the declared tools
      and their schemas, and the probes establish whether any of them reaches
      a shell. That is a direct observation of tool breadth and privilege.

What it cannot see, and why:

  Autonomy        whether a human co-signs actions is a deployment choice
  Language        whether natural language drives execution depends on the
                  client wired to the server, not on the server
  Context         environmental signals come from the deployment
  Non-Determinism a property of the model behind the client
  Opacity         depends on the operator's logging and audit setup
  Persistence     memory across sessions is a deployment property
  Identity        role assumption at runtime is configured by the operator
  Multi-Agent     whether other agents coordinate with this one is unknowable
                  from one repository
  Self-Mod        whether the agent may rewrite its own configuration is a
                  deployment permission

None of those nine is defaulted or assumed absent. They are reported as
unobserved unless an operator supplies them with --aivss-factors.

Per-rule applicability: AIVSS v0.8 section 3.3.1 says to review the ten
factors "for each vulnerability", so factors are scored per finding rather
than once per system. A rule declares the factors that amplify it; the rest
score 0.0 with the reason "not applicable to this finding class", which is a
scored value and not an assumption about the deployment.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .aivss import (
    FACTOR_KEYS,
    FACTOR_TITLE,
    NOT_APPLICABLE,
    OBSERVED,
    OPERATOR,
    FactorObservation,
    unobserved,
)

# The only factor a scan can determine on its own.
SCANNER_OBSERVABLE = ("tools",)

WHY_UNOBSERVABLE = {
    "autonomy": "whether a human co-signs actions is a deployment choice",
    "language": "depends on the client wired to the server, not the server",
    "context": "environmental signals come from the deployment",
    "non_determinism": "a property of the model behind the client",
    "opacity": "depends on the operator's logging and audit setup",
    "persistence": "memory across sessions is a deployment property",
    "identity": "runtime role assumption is configured by the operator",
    "multi_agent": "coordination with other agents is not visible in one repo",
    "self_mod": "whether the agent may rewrite its own config is a permission",
}


def observe_tools(dynamic_artifacts: Optional[Dict[str, Any]],
                  shell_proven: bool) -> Optional[FactorObservation]:
    """Score the Tools factor from what the dynamic stage saw.

    Rubric, AIVSS v0.8 section 2.3, factor 2:
      0.0  read-only tools or no external access
      0.5  mixed read/write, heavily scoped
      1.0  broad, high-authority tools

    A tool proven to reach a shell is high authority by any reading, and MCP
    Guard proves that with its own canary rather than inferring it.
    """
    if not dynamic_artifacts:
        return None
    count = dynamic_artifacts.get("tools_discovered")
    if count is None:
        return None

    if shell_proven:
        return FactorObservation(
            key="tools", status=OBSERVED, value=1.0,
            source=(f"tools/list declared {count} tool(s) and a canary probe "
                    f"proved one reaches a shell"))
    if count == 0:
        return FactorObservation(
            key="tools", status=OBSERVED, value=0.0,
            source="tools/list declared no tools")
    return FactorObservation(
        key="tools", status=OBSERVED, value=0.5,
        source=(f"tools/list declared {count} tool(s); no probe proved shell "
                f"or filesystem escape, so breadth is partial"))


def build_observations(
    rule_factors: tuple,
    dynamic_artifacts: Optional[Dict[str, Any]] = None,
    shell_proven: bool = False,
    operator_factors: Optional[Dict[str, float]] = None,
) -> Dict[str, FactorObservation]:
    """Assemble the ten factor observations for one finding.

    Precedence: operator-supplied beats observed beats not-applicable beats
    unobserved. An operator who states a factor is trusted over a guess, and
    the status records that they supplied it.
    """
    operator_factors = operator_factors or {}
    out: Dict[str, FactorObservation] = {}

    for key in FACTOR_KEYS:
        if key in operator_factors:
            out[key] = FactorObservation(
                key=key, status=OPERATOR, value=operator_factors[key],
                source="supplied by the operator with --aivss-factors")
            continue

        if key not in rule_factors:
            out[key] = FactorObservation(
                key=key, status=NOT_APPLICABLE, value=0.0,
                source="not applicable to this finding class")
            continue

        if key == "tools":
            got = observe_tools(dynamic_artifacts, shell_proven)
            if got is not None:
                out[key] = got
                continue

        out[key] = unobserved(
            key,
            WHY_UNOBSERVABLE.get(key, "not determined by this scan")
            if key not in SCANNER_OBSERVABLE
            else "the dynamic stage did not run, so tools/list was never read")

    return out


def unobserved_summary(observations: Dict[str, FactorObservation]) -> List[str]:
    return [FACTOR_TITLE[k] for k, o in observations.items() if not o.known]


def parse_operator_factors(spec: str) -> Dict[str, float]:
    """Parse --aivss-factors, e.g. "autonomy=1.0,persistence=0.5".

    Raises on an unknown factor or a value outside the rubric rather than
    silently dropping it.
    """
    from .aivss import VALID_VALUES, InvalidFactorVector

    out: Dict[str, float] = {}
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise InvalidFactorVector(
                f"expected factor=value, got {chunk!r}")
        name, raw = chunk.split("=", 1)
        name = name.strip().lower().replace("-", "_")
        if name not in FACTOR_KEYS:
            raise InvalidFactorVector(
                f"unknown factor {name!r}; expected one of {list(FACTOR_KEYS)}")
        try:
            value = float(raw)
        except ValueError:
            raise InvalidFactorVector(f"{name}: {raw!r} is not a number") from None
        if value not in VALID_VALUES:
            raise InvalidFactorVector(
                f"{name}: {value} is not one of {VALID_VALUES} "
                f"(AIVSS v0.8 section 2.3)")
        out[name] = value
    return out
