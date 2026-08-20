from pathlib import Path

import pytest
from pydantic import ValidationError

from models import AttackPlan, Scenario


def base_scenario() -> dict:
    return {
        "t9_code": "T9-25-01-S-N-CD",
        "cve": "CVE-2025-0001",
        "name": "Test RCE",
        "software": "demo",
        "lane": "network",
        "supported": True,
        "vulhub_path": "demo/cve",
        "port": 8080,
        "http_path": "/health",
        "tactics": "CD",
    }


def test_legacy_scenario_migrates_but_requires_verifier() -> None:
    scenario = Scenario.model_validate(base_scenario())
    assert scenario.environment is not None
    assert scenario.environment.path == "demo/cve"
    assert scenario.environment.service == "demo"
    assert scenario.capture.ports == [8080]
    assert "a machine-checkable verification rule is required" in scenario.runnable_errors()


def test_complete_network_scenario_is_runnable() -> None:
    raw = base_scenario()
    raw["verification"] = [
        {"type": "any_step_output", "stdout_regex": "${PROOF_TOKEN}"}
    ]
    scenario = Scenario.model_validate(raw)
    assert scenario.runnable_errors() == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("t9_code", "../../outside"),
        ("tactics", "CZ"),
        ("vulhub_path", "../outside"),
    ],
)
def test_unsafe_catalog_values_are_rejected(field: str, value: str) -> None:
    raw = base_scenario()
    raw[field] = value
    with pytest.raises(ValidationError):
        Scenario.model_validate(raw)


def test_output_directory_stays_below_root(tmp_path: Path) -> None:
    raw = base_scenario()
    raw["verification"] = [
        {"type": "any_step_output", "stdout_regex": "${PROOF_TOKEN}"}
    ]
    scenario = Scenario.model_validate(raw)
    output = scenario.output_directory(tmp_path, "run-1")
    assert output.is_relative_to(tmp_path)


def test_attack_plan_rejects_duplicate_steps_and_escaping_files() -> None:
    with pytest.raises(ValidationError):
        AttackPlan.model_validate(
            {
                "summary": "test",
                "success_rationale": "marker",
                "files": [{"path": "../escape.py", "content": ""}],
                "steps": [
                    {
                        "id": "one",
                        "argv": ["python", "/work/a.py", "${TARGET_HOST}"],
                        "expected_evidence": "marker",
                    }
                ],
            }
        )

    with pytest.raises(ValidationError):
        AttackPlan.model_validate(
            {
                "summary": "test",
                "success_rationale": "marker",
                "steps": [
                    {
                        "id": "same",
                        "argv": ["python", "-V", "${TARGET_HOST}"],
                        "expected_evidence": "marker",
                    },
                    {
                        "id": "same",
                        "argv": ["python", "-V", "${TARGET_HOST}"],
                        "expected_evidence": "marker",
                    },
                ],
            }
        )
