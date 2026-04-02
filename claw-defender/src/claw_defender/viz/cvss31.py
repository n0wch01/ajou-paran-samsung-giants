"""CVSS v3.1 vector parsing, scoring, and scenario presets (Viz / reporting)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal

from cvss import CVSS3, CVSS3Error

ScenarioId = Literal["A1", "B1", "C1"]


class CVSS31Error(ValueError):
    """Invalid or unsupported CVSS v3.1 vector string."""


@dataclass(frozen=True, slots=True)
class CVSS31Result:
    """Base metrics for a single vector (Viz-friendly)."""

    vector_string: str
    base_score: float
    base_severity: str
    cvss_json: dict[str, Any]

    @property
    def cvss_vector(self) -> str:
        """Alias matching plan/report field name `cvss_vector`."""
        return self.vector_string


# Presets align with the OpenClaw defender plan: A1 confidentiality-led, B1 availability,
# C1 critical compromise when arbitrary tool/exec is proven.
SCENARIO_CVSS_PRESETS: Final[dict[ScenarioId, tuple[str, str]]] = {
    "A1": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "Data exfiltration / RAG bypass (high confidentiality, limited integrity).",
    ),
    "B1": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "API / resource exhaustion (availability).",
    ),
    "C1": (
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "Proven arbitrary code or tool abuse with changed scope.",
    ),
}


def preset_vector(scenario_id: ScenarioId) -> str:
    """Default CVSS:3.1 vector string for a threat scenario (template for findings)."""
    return SCENARIO_CVSS_PRESETS[scenario_id][0]


def preset_rationale(scenario_id: ScenarioId) -> str:
    """Short explanation of why the preset matches the scenario axis."""
    return SCENARIO_CVSS_PRESETS[scenario_id][1]


def compute_cvss31(vector: str) -> CVSS31Result:
    """
    Parse a CVSS v3.1 vector and compute base score and official JSON fields.

    ``vector`` may omit the ``CVSS:3.1/`` prefix; it will be normalized when possible.
    """
    v = vector.strip()
    if v and not v.upper().startswith("CVSS:"):
        v = f"CVSS:3.1/{v}"

    try:
        parsed = CVSS3(v)
        parsed.check_mandatory()
    except CVSS3Error as e:
        raise CVSS31Error(str(e)) from e

    data = parsed.as_json(sort=True)
    ver = str(data.get("version") or "")
    if ver != "3.1":
        raise CVSS31Error(f"Expected CVSS 3.1 base vector, got version {ver!r}")

    cleaned = parsed.clean_vector()
    base = data.get("baseScore")
    sev = data.get("baseSeverity")
    if base is None or sev is None:
        raise CVSS31Error("CVSS library did not produce baseScore/baseSeverity")

    return CVSS31Result(
        vector_string=cleaned,
        base_score=float(base),
        base_severity=str(sev),
        cvss_json=data,
    )
