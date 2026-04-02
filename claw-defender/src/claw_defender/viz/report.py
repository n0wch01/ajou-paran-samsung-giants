"""Structured report payloads for visualization (scenarios + findings + CVSS)."""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from claw_defender.viz.cvss31 import (
    CVSS31Result,
    ScenarioId,
    compute_cvss31,
    preset_rationale,
    preset_vector,
)

VIZ_REPORT_SCHEMA_VERSION = "1"

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
)
_LONG_SECRET_RE = re.compile(r"\b(?:[A-Za-z0-9_-]{32,}|[A-Fa-f0-9]{40,})\b")


def mask_excerpt(text: str, *, max_chars: int = 2000) -> str:
    """
    Redact common sensitive patterns for Viz evidence fields.

    Not a full DLP pass; probes should still avoid shipping raw secrets.
    """
    if not text:
        return text
    out = _EMAIL_RE.sub("[redacted-email]", text)
    out = _LONG_SECRET_RE.sub("[redacted-token]", out)
    if len(out) > max_chars:
        out = out[: max_chars - 3] + "..."
    return out


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScenarioRow:
    """One row per threat scenario (summary for dashboards)."""

    scenario_id: ScenarioId
    title: str
    status: str
    summary: str
    cvss_vector: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    preset_rationale: str | None = None


@dataclass
class FindingRow:
    """One row per observation / probe outcome (plan: 소견별 행)."""

    finding_id: str
    scenario_id: ScenarioId
    title: str
    summary: str
    result: str
    cvss_vector: str
    cvss_base_score: float
    cvss_severity: str
    evidence_masked: str | None = None
    occurred_at: str | None = None
    cvss_json: dict[str, Any] | None = None

    @classmethod
    def from_vector(
        cls,
        *,
        scenario_id: ScenarioId,
        title: str,
        summary: str,
        result: str,
        vector: str,
        evidence: str | None = None,
        occurred_at: str | None = None,
        finding_id: str | None = None,
    ) -> FindingRow:
        scored = compute_cvss31(vector)
        return cls(
            finding_id=finding_id or str(uuid.uuid4()),
            scenario_id=scenario_id,
            title=title,
            summary=summary,
            result=result,
            cvss_vector=scored.vector_string,
            cvss_base_score=scored.base_score,
            cvss_severity=scored.base_severity,
            evidence_masked=mask_excerpt(evidence) if evidence else None,
            occurred_at=occurred_at,
            cvss_json=scored.cvss_json,
        )


@dataclass
class VizReport:
    """Top-level document consumed by Viz (tables, timelines, CVSS charts)."""

    scenarios: list[ScenarioRow] = field(default_factory=list)
    findings: list[FindingRow] = field(default_factory=list)
    generated_at: str = field(default_factory=_utc_now_iso)
    schema_version: str = VIZ_REPORT_SCHEMA_VERSION

    def add_finding(self, finding: FindingRow) -> None:
        self.findings.append(finding)


def scenario_row_with_preset(
    scenario_id: ScenarioId,
    *,
    title: str,
    status: str,
    summary: str,
) -> ScenarioRow:
    """Build a scenario row carrying the plan default vector and scores."""
    v = preset_vector(scenario_id)
    r = compute_cvss31(v)
    return ScenarioRow(
        scenario_id=scenario_id,
        title=title,
        status=status,
        summary=summary,
        cvss_vector=r.vector_string,
        cvss_base_score=r.base_score,
        cvss_severity=r.base_severity,
        preset_rationale=preset_rationale(scenario_id),
    )


def viz_report_to_jsonable(report: VizReport) -> dict[str, Any]:
    """Serialize for ``json.dumps`` (plain dicts / lists / scalars only)."""
    return {
        "schema_version": report.schema_version,
        "generated_at": report.generated_at,
        "scenarios": [asdict(s) for s in report.scenarios],
        "findings": [asdict(f) for f in report.findings],
    }


def attach_cvss_to_finding_dict(row: dict[str, Any]) -> dict[str, Any]:
    """
    Given a finding-like dict with ``cvss_vector`` string, fill score fields in place.

    Useful when probes build dicts instead of :class:`FindingRow`.
    """
    vec = row.get("cvss_vector")
    if not vec or not isinstance(vec, str):
        raise ValueError("row must contain string 'cvss_vector'")
    r: CVSS31Result = compute_cvss31(vec)
    out = {**row}
    out["cvss_vector"] = r.vector_string
    out["cvss_base_score"] = r.base_score
    out["cvss_severity"] = r.base_severity
    out["cvss_json"] = r.cvss_json
    return out
