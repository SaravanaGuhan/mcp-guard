"""CVSS v4.0 scoring.

Scores are never authored by hand. Each rule ships a base vector with a
justification for each non-default metric, and the score is computed from that
vector by the ``cvss`` library. ``score_for`` is the only way a Finding gets a
number, and it always returns the vector it scored, so a report can never carry
a score that disagrees with its vector.
"""

from __future__ import annotations

from typing import Tuple

from cvss import CVSS4


class InvalidVector(ValueError):
    pass


def score_for(vector: str) -> Tuple[str, float]:
    """Return ``(normalised_vector, base_score)``.

    Raises InvalidVector if the string is not a parseable CVSS 4.0 vector, so a
    typo in a rule definition fails loudly at import/test time rather than
    silently producing a plausible number.
    """
    if not vector or not vector.startswith("CVSS:4.0/"):
        raise InvalidVector(
            f"expected a CVSS:4.0 vector string, got {vector!r}"
        )
    try:
        c = CVSS4(vector)
    except Exception as exc:  # noqa: BLE001 - surface the library's message
        raise InvalidVector(f"unparseable CVSS 4.0 vector {vector!r}: {exc}") from exc
    return c.clean_vector(), float(c.base_score)
