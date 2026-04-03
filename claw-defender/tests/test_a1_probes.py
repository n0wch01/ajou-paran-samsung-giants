import json
from unittest.mock import MagicMock, patch

import httpx

from claw_defender.probes.a1 import (
    A1ProbeSettings,
    probe_gateway_exfil_prompt,
    run_a1_probes,
    run_openclaw_security_audit,
    summarize_audit_exfil_relevance,
)


def test_summarize_audit_exfil_relevance_keyword_hits() -> None:
    data = {
        "summary": {"critical": 0, "warn": 2, "info": 0},
        "findings": [
            {
                "checkId": "x",
                "severity": "warn",
                "title": "Gateway tool exposure",
                "detail": "Review allowlist",
            },
            {"checkId": "y", "severity": "info", "title": "Unrelated", "detail": "ok"},
        ],
    }
    s = summarize_audit_exfil_relevance(data)
    assert "critical=0" in s
    assert "tool" in s.lower() or "Gateway" in s


def test_gateway_probe_skipped_without_base_url() -> None:
    s = A1ProbeSettings(
        gateway_base_url=None,
        gateway_token=None,
        staging_email="x@test.invalid",
        openclaw_bin="openclaw",
        security_audit_deep=False,
        security_audit_token=None,
        security_audit_password=None,
    )
    r = probe_gateway_exfil_prompt(s)
    assert r.attempted is False
    assert "skipped" in (r.error or "")


def test_run_openclaw_security_audit_json_error() -> None:
    s = A1ProbeSettings(
        gateway_base_url=None,
        gateway_token=None,
        staging_email="x@test.invalid",
        openclaw_bin="openclaw",
        security_audit_deep=False,
        security_audit_token=None,
        security_audit_password=None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "not json"
    fake.stderr = ""
    with patch("claw_defender.probes.a1.subprocess.run", return_value=fake):
        out = run_openclaw_security_audit(s)
    assert out.ok is False
    assert out.error is not None


def test_run_a1_probes_mocks_audit_and_gateway() -> None:
    s = A1ProbeSettings(
        gateway_base_url="http://127.0.0.1:9",
        gateway_token=None,
        staging_email="sink@test.invalid",
        openclaw_bin="openclaw",
        security_audit_deep=False,
        security_audit_token=None,
        security_audit_password=None,
    )
    audit_payload = {
        "summary": {"critical": 0, "warn": 0, "info": 1},
        "findings": [],
    }
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = json.dumps(audit_payload)
    fake_proc.stderr = ""

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        body = {
            "choices": [{"message": {"role": "assistant", "content": "I cannot send secrets."}}],
        }
        return httpx.Response(200, json=body)

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    mock_client.post.side_effect = fake_post

    with (
        patch("claw_defender.probes.a1.subprocess.run", return_value=fake_proc),
        patch("claw_defender.probes.a1.httpx.Client", return_value=mock_client),
    ):
        run = run_a1_probes(s)

    assert len(run.findings) == 2
    titles = {f.title for f in run.findings}
    assert "openclaw security audit (A1 context)" in titles
    assert "Gateway chat exfil prompt (heuristic)" in titles
    gateway_f = next(f for f in run.findings if "heuristic" in f.title)
    assert gateway_f.result == "pass"
