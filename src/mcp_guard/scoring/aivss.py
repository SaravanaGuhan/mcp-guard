"""AIVSS scoring, OWASP AIVSS v0.8.

Implements "AIVSS Scoring System For OWASP Agentic AI Core Security Risks"
v0.8, published by the OWASP AIVSS project at https://aivss.owasp.org/
(assets/publications/AIVSS Scoring System For OWASP Agentic AI Core Security
Risks v0.8.pdf). Section numbers below refer to that document.

The formula, verbatim from sections 3.3 and 3.4:

    Factor_Sum = sum of the ten Risk Amplification Factors, each 0.0/0.5/1.0
    AARS       = (10 - CVSS_Base) * (Factor_Sum / 10) * ThM
    AIVSS_raw  = (CVSS_Base + AARS) * Mitigation_Factor
    AIVSS      = RoundHalfUp(AIVSS_raw, 1)

Nothing here is approximated. Weights, factor order, the 0.0/0.5/1.0 rubric,
the ThM table, the Mitigation_Factor table and the severity bands are the
spec's, not this project's.

THE OBSERVABILITY RULE
----------------------
A repository scanner can see some agentic factors and not others. Tool surface
is visible because tools/list returns the declared tools. Execution autonomy,
memory persistence, identity handling and the rest are properties of how an
operator deploys the agent, and are invisible from the code.

An unobserved factor is therefore reported as unobserved. It is NOT defaulted
to a middle value and NOT assumed absent, because either invents data. Instead
the score is emitted as a BOUND: the lower bound scores every unknown factor
0.0, the upper bound scores it 1.0, and the true AIVSS lies between them. When
every factor is known the two bounds coincide and the result is a single score.

Operators who know their deployment can supply the missing factors with
--aivss-factors; supplied values are recorded as operator-supplied rather than
observed, so a reader can tell the difference.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Dict, List, Optional, Tuple

SPEC_NAME = "OWASP AIVSS"
SPEC_VERSION = "0.8"
SPEC_TITLE = "AIVSS Scoring System For OWASP Agentic AI Core Security Risks"
SPEC_URL = "https://aivss.owasp.org/"

# Section 2.2. The order is the one the spec requires for the calculation
# vector, and the abbreviations are used in the vector string.
FACTORS: Tuple[Tuple[str, str, str], ...] = (
    ("autonomy",       "AU", "Execution Autonomy"),
    ("tools",          "TO", "External Tool Control Surface"),
    ("language",       "LA", "Natural Language Interface"),
    ("context",        "CX", "Contextual Awareness"),
    ("non_determinism", "ND", "Behavioral Non-Determinism"),
    ("opacity",        "OP", "Opacity and Reflexivity"),
    ("persistence",    "PE", "Persistent State Retention"),
    ("identity",       "ID", "Dynamic Identity"),
    ("multi_agent",    "MA", "Multi-Agent Interactions"),
    ("self_mod",       "SM", "Self-Modification"),
)
FACTOR_KEYS = tuple(k for k, _, _ in FACTORS)
FACTOR_ABBREV = {k: a for k, a, _ in FACTORS}
FACTOR_TITLE = {k: t for k, _, t in FACTORS}
ABBREV_TO_KEY = {a: k for k, a, _ in FACTORS}

# Section 2.3. The rubric admits exactly these three values.
VALID_VALUES = (0.0, 0.5, 1.0)

# Section 3.3.2, Table 4a.
THREAT_MULTIPLIER = {"attacked": 1.00, "poc": 0.97, "unreported": 0.50}
DEFAULT_THM_KEY = "poc"          # spec default: Proof-of-Concept, 0.97

# Section 3.4.1, Table 4b.
MITIGATION_FACTOR = {"none": 1.00, "partial": 0.83, "strong": 0.67}
DEFAULT_MITIGATION_KEY = "none"  # spec default: No/Weak Mitigation, 1.00

# Section 3.5.2.
BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


class InvalidFactorVector(ValueError):
    """Raised for a malformed vector or an out-of-rubric factor value."""


# ---------------------------------------------------------------------------
# Factor observations
# ---------------------------------------------------------------------------

OBSERVED = "observed"
OPERATOR = "operator-supplied"
NOT_APPLICABLE = "not-applicable"
UNOBSERVED = "unobserved"


@dataclass(frozen=True)
class FactorObservation:
    """One factor, and how its value came to be known.

    ``value`` is None exactly when ``status`` is UNOBSERVED. There is no code
    path that produces a number without a status saying where it came from.
    """

    key: str
    status: str
    value: Optional[float] = None
    source: str = ""

    def __post_init__(self) -> None:
        if self.key not in FACTOR_KEYS:
            raise InvalidFactorVector(f"unknown factor {self.key!r}")
        if self.status == UNOBSERVED:
            if self.value is not None:
                raise InvalidFactorVector(
                    f"{self.key}: an unobserved factor cannot carry a value")
            return
        if self.status not in (OBSERVED, OPERATOR, NOT_APPLICABLE):
            raise InvalidFactorVector(f"{self.key}: unknown status {self.status!r}")
        if self.value not in VALID_VALUES:
            raise InvalidFactorVector(
                f"{self.key}: value {self.value!r} is not one of "
                f"{VALID_VALUES} (AIVSS v0.8 section 2.3)")
        if not self.source:
            raise InvalidFactorVector(
                f"{self.key}: a known factor must say where its value came from")

    @property
    def known(self) -> bool:
        return self.status != UNOBSERVED

    def as_dict(self) -> dict:
        return {"factor": self.key, "name": FACTOR_TITLE[self.key],
                "status": self.status, "value": self.value,
                "source": self.source}


def unobserved(key: str, why: str = "") -> FactorObservation:
    return FactorObservation(key=key, status=UNOBSERVED, source=why)


# ---------------------------------------------------------------------------
# Vector
# ---------------------------------------------------------------------------


def to_vector(observations: Dict[str, FactorObservation]) -> str:
    """Serialise to a vector string. ``X`` marks an unobserved factor.

    Example: AIVSS:0.8/AU:X/TO:1.0/LA:X/CX:X/ND:X/OP:X/PE:X/ID:X/MA:X/SM:0.0
    """
    parts = [f"AIVSS:{SPEC_VERSION}"]
    for key in FACTOR_KEYS:
        obs = observations.get(key)
        if obs is None or not obs.known:
            parts.append(f"{FACTOR_ABBREV[key]}:X")
        else:
            parts.append(f"{FACTOR_ABBREV[key]}:{obs.value:.1f}")
    return "/".join(parts)


def parse_vector(vector: str) -> Dict[str, Optional[float]]:
    """Parse a vector back to values. Raises rather than guessing."""
    if not vector or not vector.startswith(f"AIVSS:{SPEC_VERSION}/"):
        raise InvalidFactorVector(
            f"expected a vector beginning AIVSS:{SPEC_VERSION}/, got {vector!r}")
    out: Dict[str, Optional[float]] = {}
    for chunk in vector.split("/")[1:]:
        if ":" not in chunk:
            raise InvalidFactorVector(f"malformed component {chunk!r}")
        abbrev, raw = chunk.split(":", 1)
        key = ABBREV_TO_KEY.get(abbrev)
        if key is None:
            raise InvalidFactorVector(f"unknown factor abbreviation {abbrev!r}")
        if raw == "X":
            out[key] = None
            continue
        try:
            value = float(raw)
        except ValueError:
            raise InvalidFactorVector(
                f"{abbrev}: {raw!r} is not a number or X") from None
        if value not in VALID_VALUES:
            raise InvalidFactorVector(
                f"{abbrev}: {value} is not one of {VALID_VALUES}")
        out[key] = value
    missing = [k for k in FACTOR_KEYS if k not in out]
    if missing:
        raise InvalidFactorVector(
            f"vector omits {[FACTOR_ABBREV[m] for m in missing]}; all ten "
            f"factors must appear")
    return out


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------


def _round_half_up(x: float) -> float:
    """Section 3.5.1: round half up to one decimal. 8.65 becomes 8.7."""
    return float(Decimal(repr(x)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def band(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "none"


@dataclass(frozen=True)
class AivssScore:
    """A bounded AIVSS result.

    ``complete`` is True only when every factor is known, in which case low and
    high are equal and ``score`` is a single AIVSS value. Otherwise the true
    score lies in [low, high] and the report must say so.
    """

    vector: str
    cvss_base: float
    thm: float
    thm_key: str
    mitigation: float
    mitigation_key: str
    factor_sum_low: float
    factor_sum_high: float
    aars_low: float
    aars_high: float
    low: float
    high: float
    observations: Tuple[FactorObservation, ...]
    spec: str = f"{SPEC_NAME} v{SPEC_VERSION}"

    @property
    def complete(self) -> bool:
        return all(o.known for o in self.observations)

    @property
    def score(self) -> Optional[float]:
        """The single AIVSS score, or None when factors are unobserved."""
        return self.low if self.complete else None

    @property
    def unobserved_factors(self) -> List[str]:
        return [o.key for o in self.observations if not o.known]

    @property
    def band_low(self) -> str:
        return band(self.low)

    @property
    def band_high(self) -> str:
        return band(self.high)

    def summary(self) -> str:
        if self.complete:
            return f"{self.low:.1f} ({self.band_low}), {self.spec}"
        names = ", ".join(FACTOR_TITLE[k] for k in self.unobserved_factors)
        return (f"partial AIVSS {self.low:.1f} to {self.high:.1f}, {self.spec}. "
                f"{len(self.unobserved_factors)} of 10 factors could not be "
                f"determined by scanning: {names}")

    def as_dict(self) -> dict:
        return {
            "spec": self.spec,
            "spec_title": SPEC_TITLE,
            "spec_url": SPEC_URL,
            "vector": self.vector,
            "complete": self.complete,
            "partial": not self.complete,
            "score": self.score,
            "score_low": self.low,
            "score_high": self.high,
            "severity_low": self.band_low,
            "severity_high": self.band_high,
            "cvss_base": self.cvss_base,
            "threat_multiplier": {"key": self.thm_key, "value": self.thm},
            "mitigation_factor": {"key": self.mitigation_key,
                                  "value": self.mitigation},
            "factor_sum_low": self.factor_sum_low,
            "factor_sum_high": self.factor_sum_high,
            "aars_low": self.aars_low,
            "aars_high": self.aars_high,
            "unobserved_factors": self.unobserved_factors,
            "factors": [o.as_dict() for o in self.observations],
        }


def score(
    cvss_base: float,
    observations: Dict[str, FactorObservation],
    *,
    thm_key: str = DEFAULT_THM_KEY,
    mitigation_key: str = DEFAULT_MITIGATION_KEY,
) -> AivssScore:
    """Compute a bounded AIVSS score from factor observations.

    The score is always derived from the factor vector. There is no path that
    accepts a number directly, for the same reason CVSS scores are computed
    from vectors here: a score nobody can recompute is not evidence.
    """
    if not 0.0 <= cvss_base <= 10.0:
        raise InvalidFactorVector(
            f"CVSS_Base must be between 0 and 10, got {cvss_base}")
    if thm_key not in THREAT_MULTIPLIER:
        raise InvalidFactorVector(
            f"unknown exploit maturity {thm_key!r}; expected one of "
            f"{sorted(THREAT_MULTIPLIER)}")
    if mitigation_key not in MITIGATION_FACTOR:
        raise InvalidFactorVector(
            f"unknown mitigation strength {mitigation_key!r}; expected one of "
            f"{sorted(MITIGATION_FACTOR)}")

    ordered = tuple(
        observations.get(k) or unobserved(k, "not determined by this scan")
        for k in FACTOR_KEYS
    )
    vector = to_vector({o.key: o for o in ordered})
    thm = THREAT_MULTIPLIER[thm_key]
    mitigation = MITIGATION_FACTOR[mitigation_key]

    known = sum(o.value for o in ordered if o.known)          # type: ignore[misc]
    unknown_count = sum(1 for o in ordered if not o.known)

    # Bound rather than default: unknown factors contribute 0.0 at the low end
    # and 1.0 at the high end. Section 3.3.1.
    fs_low = known
    fs_high = known + unknown_count

    def aivss_for(factor_sum: float) -> Tuple[float, float]:
        aars = (10.0 - cvss_base) * (factor_sum / 10.0) * thm       # 3.3.1
        raw = (cvss_base + aars) * mitigation                       # 3.4
        return aars, _round_half_up(raw)                            # 3.5.1

    aars_low, low = aivss_for(fs_low)
    aars_high, high = aivss_for(fs_high)

    return AivssScore(
        vector=vector, cvss_base=cvss_base, thm=thm, thm_key=thm_key,
        mitigation=mitigation, mitigation_key=mitigation_key,
        factor_sum_low=fs_low, factor_sum_high=fs_high,
        aars_low=round(aars_low, 4), aars_high=round(aars_high, 4),
        low=low, high=high, observations=ordered,
    )


def score_from_vector(cvss_base: float, vector: str, **kwargs) -> AivssScore:
    """Recompute from a serialised vector. Used by the tests to prove that a
    reported score is reproducible from its vector alone."""
    values = parse_vector(vector)
    obs: Dict[str, FactorObservation] = {}
    for key, value in values.items():
        if value is None:
            obs[key] = unobserved(key, "unobserved in vector")
        else:
            obs[key] = FactorObservation(key=key, status=OBSERVED, value=value,
                                         source="vector")
    return score(cvss_base, obs, **kwargs)
