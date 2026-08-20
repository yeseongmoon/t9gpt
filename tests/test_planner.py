import json
import sys
from types import SimpleNamespace

import pytest

from models import AttackPlan, Scenario
from planner import (
    ClaudePlannerBackend,
    OpenAIPlannerBackend,
    PlannerError,
    build_planning_prompt,
    validate_plan_policy,
)


def scenario() -> Scenario:
    return Scenario.model_validate(
        {
            "t9_code": "T9-25-01-S-N-CD",
            "cve": "CVE-2025-0001",
            "name": "Test RCE",
            "software": "demo",
            "lane": "network",
            "supported": True,
            "vulhub_path": "demo/cve",
            "port": 8080,
            "tactics": "CD",
            "verification": [
                {"type": "any_step_output", "stdout_regex": "${PROOF_TOKEN}"}
            ],
        }
    )


def plan(argv: list[str]) -> AttackPlan:
    return AttackPlan.model_validate(
        {
            "summary": "minimal reproduction",
            "success_rationale": "prints marker",
            "steps": [
                {
                    "id": "exploit",
                    "argv": argv,
                    "expected_evidence": "proof marker",
                }
            ],
        }
    )


def test_policy_accepts_target_scoped_command() -> None:
    validate_plan_policy(
        plan(["python", "/work/poc.py", "${TARGET_HOST}", "${TARGET_PORT}"]),
        scenario(),
    )


def test_policy_rejects_scanner_and_literal_url() -> None:
    with pytest.raises(PlannerError, match="out-of-scope"):
        validate_plan_policy(plan(["nmap", "${TARGET_HOST}"]), scenario())
    with pytest.raises(PlannerError, match="literal URL"):
        validate_plan_policy(
            plan(["python", "/work/poc.py", "https://example.com", "${TARGET_HOST}"]),
            scenario(),
        )


def test_prompt_contains_verifier_and_prior_observation() -> None:
    prompt = build_planning_prompt(
        scenario(),
        "T9_token",
        "Vulhub instructions",
        [{"attempt": 1, "error": "marker missing"}],
    )
    assert "T9_token" in prompt
    assert "Vulhub instructions" in prompt
    assert "marker missing" in prompt


def test_claude_backend_parses_structured_output_and_tracks_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = plan(["python", "/work/poc.py", "${TARGET_HOST}"])
    envelope = {
        "structured_output": candidate.model_dump(mode="json"),
        "total_cost_usd": 0.12,
        "usage": {"input_tokens": 100, "output_tokens": 50},
    }
    monkeypatch.setattr("planner.shutil.which", lambda _: "/usr/bin/claude")
    monkeypatch.setattr(
        "planner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(envelope), stderr=""
        ),
    )
    backend = ClaudePlannerBackend(scenario())
    assert backend.propose("prompt") == candidate
    assert backend.usage() == {
        "calls": 1,
        "input_tokens": 100,
        "output_tokens": 50,
        "reported_cost_usd": 0.12,
    }


def test_openai_backend_uses_structured_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = plan(["python", "/work/poc.py", "${TARGET_HOST}"])
    response = SimpleNamespace(
        output_parsed=candidate,
        usage=SimpleNamespace(input_tokens=80, output_tokens=40),
    )
    fake_client = SimpleNamespace(
        responses=SimpleNamespace(parse=lambda **kwargs: response)
    )
    fake_module = SimpleNamespace(OpenAI=lambda **kwargs: fake_client)
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    raw = scenario().model_dump(mode="json")
    raw["planner"]["provider"] = "openai"
    raw["planner"]["model"] = "gpt-test"
    backend = OpenAIPlannerBackend(Scenario.model_validate(raw))
    assert backend.propose("prompt") == candidate
    assert backend.usage()["input_tokens"] == 80
