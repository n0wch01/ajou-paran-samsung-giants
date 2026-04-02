"""Visualization: scenario rows, CVSS, timelines, masked excerpts for reports."""

from claw_defender.viz.cvss31 import (
    CVSS31Error,
    CVSS31Result,
    SCENARIO_CVSS_PRESETS,
    ScenarioId,
    compute_cvss31,
    preset_rationale,
    preset_vector,
)
from claw_defender.viz.report import (
    VIZ_REPORT_SCHEMA_VERSION,
    FindingRow,
    ScenarioRow,
    VizReport,
    attach_cvss_to_finding_dict,
    mask_excerpt,
    scenario_row_with_preset,
    viz_report_to_jsonable,
)

__all__ = [
    "CVSS31Error",
    "CVSS31Result",
    "FindingRow",
    "SCENARIO_CVSS_PRESETS",
    "ScenarioId",
    "ScenarioRow",
    "VIZ_REPORT_SCHEMA_VERSION",
    "VizReport",
    "attach_cvss_to_finding_dict",
    "compute_cvss31",
    "mask_excerpt",
    "preset_rationale",
    "preset_vector",
    "scenario_row_with_preset",
    "viz_report_to_jsonable",
]
