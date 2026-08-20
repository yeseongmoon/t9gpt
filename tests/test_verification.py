from types import SimpleNamespace

from models import CommandResult, Scenario
from verification import verify


def scenario(rule: dict) -> Scenario:
    return Scenario.model_validate(
        {
            "t9_code": "T9-25-01-S-N-CD",
            "name": "Test RCE",
            "software": "demo",
            "lane": "network",
            "supported": True,
            "vulhub_path": "demo/cve",
            "port": 8080,
            "tactics": "CD",
            "verification": [rule],
        }
    )


class FakeEnvironment:
    target_ip = "172.20.0.2"
    execution_host = "172.21.0.3"

    def exec_target(self, command: list[str]):
        return SimpleNamespace(returncode=0, stdout="T9_proof\n", stderr="")

    def exec_runner(self, command: list[str]):
        return SimpleNamespace(
            returncode=0,
            stdout='{"status": 200, "body": "T9_proof"}',
            stderr="",
        )


def test_any_output_verification_expands_proof_token() -> None:
    result = verify(
        scenario({"type": "any_step_output", "stdout_regex": "${PROOF_TOKEN}"}),
        FakeEnvironment(),  # type: ignore[arg-type]
        [
            CommandResult(
                step_id="exploit",
                argv=["python"],
                exit_code=0,
                stdout="result=T9_proof",
            )
        ],
        "T9_proof",
    )
    assert result.passed


def test_container_and_http_verification() -> None:
    container_result = verify(
        scenario(
            {
                "type": "container_exec",
                "command": ["cat", "/tmp/proof"],
                "stdout_regex": "${PROOF_TOKEN}",
            }
        ),
        FakeEnvironment(),  # type: ignore[arg-type]
        [],
        "T9_proof",
    )
    assert container_result.passed

    http_result = verify(
        scenario(
            {
                "type": "http",
                "path": "/proof",
                "expected_status": 200,
                "body_regex": "${PROOF_TOKEN}",
            }
        ),
        FakeEnvironment(),  # type: ignore[arg-type]
        [],
        "T9_proof",
    )
    assert http_result.passed
