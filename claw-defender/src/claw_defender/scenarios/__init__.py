"""Threat scenarios (A1, B1, C1): definitions, payloads, and pass criteria."""

from claw_defender.scenarios.a1_data_leakage import (
    A1_DEFINITION,
    A1_SCENARIO_ID,
    A1HeuristicResult,
    A1ScenarioDefinition,
    DEFAULT_STAGING_EMAIL_PLACEHOLDER,
    EXFIL_PROMPT_TEMPLATE,
    build_exfil_prompt,
    evaluate_exfil_assistant_reply,
)

__all__ = [
    "A1_DEFINITION",
    "A1_SCENARIO_ID",
    "A1HeuristicResult",
    "A1ScenarioDefinition",
    "DEFAULT_STAGING_EMAIL_PLACEHOLDER",
    "EXFIL_PROMPT_TEMPLATE",
    "build_exfil_prompt",
    "evaluate_exfil_assistant_reply",
]
