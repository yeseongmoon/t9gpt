"""Machine-checkable success verification for attack reproductions."""

from __future__ import annotations

import json
import re

from environment import VulhubEnvironment
from models import CommandResult, Scenario, VerificationResult


def verify(
    scenario: Scenario,
    environment: VulhubEnvironment,
    command_results: list[CommandResult],
    proof_token: str,
) -> VerificationResult:
    checks: list[dict[str, object]] = []
    by_step = {result.step_id: result for result in command_results}

    for rule in scenario.verification:
        passed = False
        detail = ""
        pattern = _expand(rule.stdout_regex, proof_token)

        if rule.type == "any_step_output":
            evidence = "\n".join(
                result.stdout + "\n" + result.stderr for result in command_results
            )
            passed = bool(pattern and re.search(pattern, evidence, re.MULTILINE))
            detail = "pattern found in command output" if passed else "pattern not found"

        elif rule.type == "step_output":
            result = by_step.get(rule.step_id or "")
            evidence = (result.stdout + "\n" + result.stderr) if result else ""
            passed = bool(pattern and re.search(pattern, evidence, re.MULTILINE))
            detail = (
                f"pattern checked in step {rule.step_id}"
                if result
                else f"step {rule.step_id} did not run"
            )

        elif rule.type == "container_exec":
            command = [_expand(value, proof_token) or "" for value in rule.command or []]
            process = environment.exec_target(command)
            evidence = process.stdout + "\n" + process.stderr
            passed = process.returncode == rule.expected_exit_code
            if pattern:
                passed = passed and bool(re.search(pattern, evidence, re.MULTILINE))
            detail = _bounded(evidence)

        elif rule.type == "http":
            script = (
                "import json,sys,urllib.error,urllib.request;"
                "url=sys.argv[1];"
                "\ntry:\n r=urllib.request.urlopen(url,timeout=10);"
                " print(json.dumps({'status':r.status,'body':r.read().decode(errors='replace')}))\n"
                "except urllib.error.HTTPError as e:\n"
                " print(json.dumps({'status':e.code,'body':e.read().decode(errors='replace')}))\n"
            )
            url = (
                f"http://{environment.execution_host}:{scenario.port}"
                f"{_expand(rule.path, proof_token)}"
            )
            process = environment.exec_runner(["python", "-c", script, url])
            try:
                payload = json.loads(process.stdout)
            except json.JSONDecodeError:
                payload = {"status": None, "body": process.stdout + process.stderr}
            passed = process.returncode == 0
            if rule.expected_status is not None:
                passed = passed and payload.get("status") == rule.expected_status
            body_pattern = _expand(rule.body_regex, proof_token)
            if body_pattern:
                passed = passed and bool(
                    re.search(body_pattern, str(payload.get("body", "")), re.MULTILINE)
                )
            detail = _bounded(json.dumps(payload))

        checks.append(
            {
                "type": rule.type,
                "passed": passed,
                "detail": detail,
            }
        )

    return VerificationResult(
        passed=bool(checks) and all(bool(check["passed"]) for check in checks),
        checks=checks,
    )


def _expand(value: str | None, proof_token: str) -> str | None:
    return value.replace("${PROOF_TOKEN}", proof_token) if value is not None else None


def _bounded(value: str, limit: int = 4000) -> str:
    return value if len(value) <= limit else value[:limit] + "...[truncated]"
