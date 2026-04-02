import json

import pytest

from claw_defender.viz.cvss31 import preset_vector
from claw_defender.viz.report import (
    FindingRow,
    VizReport,
    attach_cvss_to_finding_dict,
    mask_excerpt,
    scenario_row_with_preset,
    viz_report_to_jsonable,
)


def test_mask_excerpt_redacts_email_and_truncates() -> None:
    long = "x" * 2500
    m = mask_excerpt(f"Contact attacker@evil.com key {long}", max_chars=100)
    assert "attacker@" not in m
    assert "[redacted-email]" in m
    assert len(m) <= 100


def test_finding_row_from_vector() -> None:
    f = FindingRow.from_vector(
        scenario_id="B1",
        title="Large mail payload",
        summary="Probe sent oversized body",
        result="blocked",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        evidence="token abcdefghijklmnopqrstuvwxyz0123456789abcdef",
    )
    assert f.cvss_base_score > 0
    assert f.evidence_masked is not None
    assert "abcdefghijklmnopqrstuvwxyz0123456789abcdef" not in f.evidence_masked


def test_viz_report_json_roundtrip() -> None:
    rep = VizReport(
        scenarios=[
            scenario_row_with_preset(
                "A1",
                title="RAG exfil",
                status="pending",
                summary="Not run",
            )
        ],
    )
    rep.add_finding(
        FindingRow.from_vector(
            scenario_id="A1",
            title="Exfil attempt",
            summary="Agent offered to email chunks",
            result="fail",
            vector=preset_vector("A1"),
        )
    )
    raw = json.dumps(viz_report_to_jsonable(rep))
    data = json.loads(raw)
    assert data["schema_version"] == "1"
    assert len(data["scenarios"]) == 1
    assert data["scenarios"][0]["cvss_base_score"] is not None
    assert len(data["findings"]) == 1
    assert data["findings"][0]["cvss_vector"].startswith("CVSS:3.1/")


def test_attach_cvss_to_finding_dict() -> None:
    row = {"cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "foo": 1}
    filled = attach_cvss_to_finding_dict(row)
    assert filled["foo"] == 1
    assert filled["cvss_base_score"] == pytest.approx(7.5)
