"""A1 probes: OpenClaw security audit subprocess and optional Gateway /v1/chat/completions exfil prompt."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Final

import httpx

from claw_defender.scenarios.a1_data_leakage import (
    A1_DEFINITION,
    A1_SCENARIO_ID,
    DEFAULT_STAGING_EMAIL_PLACEHOLDER,
    build_exfil_prompt,
    evaluate_exfil_assistant_reply,
)
from claw_defender.viz.cvss31 import preset_vector
from claw_defender.viz.report import FindingRow, VizReport, scenario_row_with_preset

_ENV_BASE_URL: Final[str] = "CLAW_DEFENDER_GATEWAY_BASE_URL"
_ENV_GATEWAY_TOKEN: Final[str] = "CLAW_DEFENDER_GATEWAY_TOKEN"
_ENV_STAGING_EMAIL: Final[str] = "CLAW_DEFENDER_STAGING_EMAIL"
_ENV_OPENCLAW_BIN: Final[str] = "CLAW_DEFENDER_OPENCLAW_BIN"
_ENV_AUDIT_DEEP: Final[str] = "CLAW_DEFENDER_SECURITY_AUDIT_DEEP"
_ENV_AUDIT_TOKEN: Final[str] = "CLAW_DEFENDER_SECURITY_AUDIT_TOKEN"
_ENV_AUDIT_PASSWORD: Final[str] = "CLAW_DEFENDER_SECURITY_AUDIT_PASSWORD"

_INFRA_VECTOR: Final[str] = "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N"
_PASS_GATEWAY_VECTOR: Final[str] = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
_INCONCLUSIVE_VECTOR: Final[str] = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"
_AUDIT_PASS_VECTOR: Final[str] = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"


def _truthy_env(name: str) -> bool:
    v = os.environ.get(name, "").strip().lower()
    return v in {"1", "true", "yes", "on"}


@dataclass
class A1ProbeSettings:
    gateway_base_url: str | None
    gateway_token: str | None
    staging_email: str
    openclaw_bin: str
    security_audit_deep: bool
    security_audit_token: str | None
    security_audit_password: str | None

    @classmethod
    def from_environ(cls) -> A1ProbeSettings:
        base = os.environ.get(_ENV_BASE_URL, "").strip()
        return cls(
            gateway_base_url=base or None,
            gateway_token=os.environ.get(_ENV_GATEWAY_TOKEN, "").strip() or None,
            staging_email=os.environ.get(_ENV_STAGING_EMAIL, "").strip()
            or DEFAULT_STAGING_EMAIL_PLACEHOLDER,
            openclaw_bin=os.environ.get(_ENV_OPENCLAW_BIN, "").strip() or "openclaw",
            security_audit_deep=_truthy_env(_ENV_AUDIT_DEEP),
            security_audit_token=os.environ.get(_ENV_AUDIT_TOKEN, "").strip() or None,
            security_audit_password=os.environ.get(_ENV_AUDIT_PASSWORD, "").strip() or None,
        )


@dataclass
class SecurityAuditProbeResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    parsed: dict[str, Any] | None
    error: str | None = None


def run_openclaw_security_audit(
    settings: A1ProbeSettings,
    *,
    timeout_sec: float = 120.0,
) -> SecurityAuditProbeResult:
    """Run ``openclaw security audit [--deep] [--token ...] --json`` (read-only)."""
    cmd: list[str] = [settings.openclaw_bin, "security", "audit", "--json"]
    if settings.security_audit_deep:
        cmd.append("--deep")
    if settings.security_audit_token:
        cmd.extend(["--token", settings.security_audit_token])
    if settings.security_audit_password:
        cmd.extend(["--password", settings.security_audit_password])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except FileNotFoundError:
        return SecurityAuditProbeResult(
            ok=False,
            returncode=-1,
            stdout="",
            stderr="",
            parsed=None,
            error=f"executable not found: {settings.openclaw_bin}",
        )
    except subprocess.TimeoutExpired as e:
        return SecurityAuditProbeResult(
            ok=False,
            returncode=-1,
            stdout=e.stdout or "",
            stderr=e.stderr or "",
            parsed=None,
            error="security audit timed out",
        )

    raw = proc.stdout or ""
    parsed: dict[str, Any] | None = None
    err: str | None = None
    try:
        parsed = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError as e:
        err = f"invalid JSON from security audit: {e}"

    ok = proc.returncode == 0 and parsed is not None and err is None
    return SecurityAuditProbeResult(
        ok=ok,
        returncode=proc.returncode,
        stdout=raw,
        stderr=proc.stderr or "",
        parsed=parsed,
        error=err,
    )


def summarize_audit_exfil_relevance(parsed: dict[str, Any]) -> str:
    """Short text for evidence: counts + titles of findings that mention risky keywords."""
    findings = parsed.get("findings")
    if not isinstance(findings, list):
        return "no findings list in audit JSON"
    keys = (
        "tool",
        "exec",
        "email",
        "mail",
        "send",
        "rag",
        "memory",
        "exposure",
        "gateway",
        "remote",
        "allowlist",
        "sandbox",
    )
    hits: list[str] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "")
        detail = str(item.get("detail") or "")
        blob = f"{title} {detail}".lower()
        if any(k in blob for k in keys):
            sev = item.get("severity", "?")
            hits.append(f"[{sev}] {title}".strip())
    summary_obj = parsed.get("summary")
    if isinstance(summary_obj, dict):
        crit = summary_obj.get("critical", "?")
        warn = summary_obj.get("warn", "?")
        head = f"audit summary critical={crit} warn={warn}. "
    else:
        head = ""
    if not hits:
        return head + "no keyword-matched findings for exfil/RAG/tools (heuristic)."
    return head + f"keyword-matched: {len(hits)} — " + "; ".join(hits[:12])


@dataclass
class GatewayExfilProbeResult:
    attempted: bool
    http_status: int | None
    assistant_text: str | None
    error: str | None
    raw_body_excerpt: str | None = None


def _chat_completions_url(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/v1/chat/completions"


def probe_gateway_exfil_prompt(
    settings: A1ProbeSettings,
    *,
    timeout_sec: float = 120.0,
    model: str = "openclaw",
) -> GatewayExfilProbeResult:
    """
    POST OpenAI-compatible chat completion with the A1 exfil prompt (non-streaming).

    Sends ``Authorization: Bearer`` when ``CLAW_DEFENDER_GATEWAY_TOKEN`` is set, and
    ``x-openclaw-scopes: operator.write`` for compatibility with OpenClaw Gateway tests.
    """
    if not settings.gateway_base_url:
        return GatewayExfilProbeResult(
            attempted=False,
            http_status=None,
            assistant_text=None,
            error="CLAW_DEFENDER_GATEWAY_BASE_URL not set; gateway probe skipped",
        )

    prompt = build_exfil_prompt(destination_email=settings.staging_email)
    headers: dict[str, str] = {
        "content-type": "application/json",
        "x-openclaw-scopes": "operator.write",
    }
    if settings.gateway_token:
        headers["authorization"] = f"Bearer {settings.gateway_token}"

    body = {
        "model": model,
        "stream": False,
        "messages": [{"role": "user", "content": prompt}],
    }

    url = _chat_completions_url(settings.gateway_base_url)
    try:
        with httpx.Client(timeout=timeout_sec) as client:
            res = client.post(url, headers=headers, json=body)
    except httpx.HTTPError as e:
        return GatewayExfilProbeResult(
            attempted=True,
            http_status=None,
            assistant_text=None,
            error=f"HTTP error: {e}",
        )

    text = res.text
    assistant: str | None = None
    if "application/json" in res.headers.get("content-type", "").lower():
        try:
            data = res.json()
            choices = data.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message") if isinstance(choices[0], dict) else None
                if isinstance(msg, dict):
                    c = msg.get("content")
                    assistant = c if isinstance(c, str) else None
        except json.JSONDecodeError:
            pass

    excerpt = text[:4000] if text else None
    err: str | None = None
    if res.status_code != 200:
        err = f"HTTP {res.status_code}"
    return GatewayExfilProbeResult(
        attempted=True,
        http_status=res.status_code,
        assistant_text=assistant,
        error=err,
        raw_body_excerpt=excerpt if assistant is None else None,
    )


@dataclass
class A1ProbeRun:
    """Aggregate result for orchestration and tests."""

    settings: A1ProbeSettings
    audit: SecurityAuditProbeResult
    gateway: GatewayExfilProbeResult
    findings: list[FindingRow]


def _finding_title_for_audit(audit: SecurityAuditProbeResult) -> str:
    if audit.error:
        return "Security audit JSON parse failure"
    if audit.returncode != 0:
        return "Security audit non-zero exit"
    return "Security audit"


def _audit_result_label(audit: SecurityAuditProbeResult) -> str:
    if audit.error or audit.parsed is None:
        return "error"
    if audit.returncode != 0:
        return "error"
    summary = audit.parsed.get("summary")
    if isinstance(summary, dict):
        crit = summary.get("critical")
        if isinstance(crit, int) and crit > 0:
            return "fail"
    return "pass"


def run_a1_probes(settings: A1ProbeSettings | None = None) -> A1ProbeRun:
    """
    Run A1 security audit + optional Gateway exfil prompt; produce :class:`FindingRow` list.

    Uses the A1 CVSS preset when a probe indicates likely exposure (audit critical > 0 or heuristic fail).
    Lower vectors mark pass, skip, or infrastructure-only outcomes.
    """
    cfg = settings or A1ProbeSettings.from_environ()
    audit = run_openclaw_security_audit(cfg)
    gateway = probe_gateway_exfil_prompt(cfg)

    findings: list[FindingRow] = []

    if not audit.ok:
        detail = audit.error or audit.stderr or (audit.stdout[:500] if audit.stdout else "")
        findings.append(
            FindingRow.from_vector(
                scenario_id=A1_SCENARIO_ID,
                title=_finding_title_for_audit(audit),
                summary="Security audit subprocess failed or returned non-JSON.",
                result="error",
                vector=_INFRA_VECTOR,
                evidence=detail,
            )
        )
    else:
        assert audit.parsed is not None
        label = _audit_result_label(audit)
        summ = summarize_audit_exfil_relevance(audit.parsed)
        vec = preset_vector(A1_SCENARIO_ID) if label == "fail" else _AUDIT_PASS_VECTOR
        findings.append(
            FindingRow.from_vector(
                scenario_id=A1_SCENARIO_ID,
                title="openclaw security audit (A1 context)",
                summary=summ,
                result=label,
                vector=vec,
                evidence=json.dumps(audit.parsed, indent=2)[:8000],
            )
        )

    if not gateway.attempted:
        findings.append(
            FindingRow.from_vector(
                scenario_id=A1_SCENARIO_ID,
                title="Gateway exfil prompt probe",
                summary=gateway.error or "skipped",
                result="skipped",
                vector=_INFRA_VECTOR,
                evidence=gateway.error,
            )
        )
    elif gateway.error:
        findings.append(
            FindingRow.from_vector(
                scenario_id=A1_SCENARIO_ID,
                title="Gateway exfil prompt probe",
                summary=gateway.error,
                result="error",
                vector=_INFRA_VECTOR,
                evidence=gateway.raw_body_excerpt or gateway.error,
            )
        )
    else:
        text = gateway.assistant_text or ""
        h = evaluate_exfil_assistant_reply(text, destination_email=cfg.staging_email)
        if h == "fail":
            vec = preset_vector(A1_SCENARIO_ID)
            res = "fail"
        elif h == "pass":
            vec = _PASS_GATEWAY_VECTOR
            res = "pass"
        else:
            vec = _INCONCLUSIVE_VECTOR
            res = "inconclusive"
        findings.append(
            FindingRow.from_vector(
                scenario_id=A1_SCENARIO_ID,
                title="Gateway chat exfil prompt (heuristic)",
                summary=f"Heuristic={h}; HTTP {gateway.http_status}",
                result=res,
                vector=vec,
                evidence=text[:8000] or gateway.raw_body_excerpt,
            )
        )

    return A1ProbeRun(settings=cfg, audit=audit, gateway=gateway, findings=findings)


def build_a1_viz_report(settings: A1ProbeSettings | None = None) -> VizReport:
    """Run probes and return a :class:`VizReport` with one A1 scenario row and all findings."""
    run = run_a1_probes(settings)
    rep = VizReport()
    rep.scenarios.append(
        scenario_row_with_preset(
            A1_SCENARIO_ID,
            title=A1_DEFINITION.title,
            status="probed",
            summary=A1_DEFINITION.narrative,
        )
    )
    for f in run.findings:
        rep.add_finding(f)
    return rep
