"""Provider-neutral, structured attack-reproduction planning."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from models import AttackPlan, Scenario

SYSTEM_PROMPT = """\
You are the planning component of T9-GPT, an authorized attack-traffic dataset
generator operating only against the disposable Vulhub target described below.

Your job is NOT to perform a penetration test. Produce the smallest reproducible
procedure that demonstrates only the named vulnerability.

Mandatory constraints:
- Do not scan ports, enumerate directories, brute-force, test unrelated CVEs, or
  perform post-exploitation, persistence, privilege escalation, credential
  collection, lateral movement, denial of service, or destructive actions.
- Use only ${TARGET_HOST}, ${TARGET_PORT}, and optional ${PROOF_TOKEN}
  placeholders for runtime-specific values. Never invent other targets.
- Prove execution harmlessly with identity/version output or the unique
  ${PROOF_TOKEN}. Temporary marker files must be under /tmp.
- Commands run as an unprivileged user in a disposable Python container with
  generated files mounted at /work and a writable /tmp.
- Prefer a Python standard-library script when a request needs multipart,
  encoding, or multiple HTTP operations. Do not install packages.
- argv is executed directly without a shell. If a generated script is needed,
  put it in files and invoke it as ["python", "/work/<name>.py", ...].
- Stop immediately after obtaining evidence required by the verifier.
- Every expected_evidence field must state the specific harmless proof expected.
"""


class PlannerError(RuntimeError):
    """Raised when a provider cannot produce a valid attack plan."""


class PlannerBackend(ABC):
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.spent_usd = 0.0

    @abstractmethod
    def propose(self, prompt: str) -> AttackPlan:
        """Return one schema-valid candidate plan."""

    def usage(self) -> dict[str, int | float]:
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "reported_cost_usd": round(self.spent_usd, 6),
        }


class ClaudePlannerBackend(PlannerBackend):
    def propose(self, prompt: str) -> AttackPlan:
        claude = shutil.which("claude")
        if not claude:
            raise PlannerError("Claude CLI is not installed or not on PATH")

        schema = json.dumps(AttackPlan.model_json_schema(), separators=(",", ":"))
        tools = "WebSearch" if self.scenario.planner.allow_public_research else ""
        remaining_budget = self.scenario.planner.budget_usd - self.spent_usd
        if remaining_budget <= 0:
            raise PlannerError("Claude planning budget is exhausted")
        cmd = [
            claude,
            "--print",
            "--model",
            self.scenario.planner.model,
            "--output-format",
            "json",
            "--json-schema",
            schema,
            "--max-budget-usd",
            str(remaining_budget),
            "--no-session-persistence",
            "--safe-mode",
            "--tools",
            tools,
            "--system-prompt",
            SYSTEM_PROMPT,
            prompt,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.scenario.planner.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PlannerError("Claude planning request timed out") from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise PlannerError(f"Claude planning failed: {detail[:1000]}")

        try:
            envelope = json.loads(result.stdout)
            self.calls += 1
            self.spent_usd += float(envelope.get("total_cost_usd", 0) or 0)
            usage = envelope.get("usage", {}) or {}
            self.input_tokens += int(usage.get("input_tokens", 0) or 0)
            self.output_tokens += int(usage.get("output_tokens", 0) or 0)
            raw = envelope.get("structured_output", envelope.get("result", envelope))
            if isinstance(raw, str):
                raw = _extract_json(raw)
            return AttackPlan.model_validate(raw)
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            raise PlannerError(f"Claude returned an invalid attack plan: {exc}") from exc


class OpenAIPlannerBackend(PlannerBackend):
    def propose(self, prompt: str) -> AttackPlan:
        if not os.environ.get("OPENAI_API_KEY"):
            raise PlannerError("OPENAI_API_KEY is required for the OpenAI planner")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise PlannerError("OpenAI planner requires the 'openai' package") from exc

        client = OpenAI(timeout=self.scenario.planner.timeout_seconds)
        kwargs: dict[str, Any] = {
            "model": self.scenario.planner.model,
            "input": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "text_format": AttackPlan,
            "max_output_tokens": self.scenario.planner.max_output_tokens,
        }
        if self.scenario.planner.allow_public_research:
            kwargs["tools"] = [{"type": "web_search"}]
        try:
            response = client.responses.parse(**kwargs)
        except Exception as exc:
            raise PlannerError(f"OpenAI planning failed: {exc}") from exc
        plan = response.output_parsed
        if plan is None:
            raise PlannerError("OpenAI returned no structured attack plan")
        self.calls += 1
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
            self.output_tokens += int(getattr(usage, "output_tokens", 0) or 0)
        return AttackPlan.model_validate(plan)


def build_planner(scenario: Scenario) -> PlannerBackend:
    if scenario.planner.provider == "claude":
        return ClaudePlannerBackend(scenario)
    if scenario.planner.provider == "openai":
        return OpenAIPlannerBackend(scenario)
    raise PlannerError(f"unsupported planner provider: {scenario.planner.provider}")


def build_planning_prompt(
    scenario: Scenario,
    proof_token: str,
    vulhub_readme: str,
    observations: list[dict[str, object]],
) -> str:
    environment = scenario.environment
    if environment is None:
        raise PlannerError("scenario has no environment")
    verifier = [rule.model_dump(mode="json") for rule in scenario.verification]
    history = json.dumps(observations, indent=2) if observations else "No prior attempts."
    return f"""\
SCENARIO
- T9 code: {scenario.t9_code}
- Name: {scenario.name}
- CVE/advisory: {scenario.cve or "not assigned"}
- Software: {scenario.software}
- Vulhub path: {environment.path}
- Target port: {environment.target_port}
- Required proof token: {proof_token}
- Maximum steps: {scenario.planner.max_steps}

MACHINE VERIFIER
{json.dumps(verifier, indent=2)}

LOCAL VULHUB DOCUMENTATION
{_bounded(vulhub_readme, 30_000)}

PRIOR ATTEMPT OBSERVATIONS
{_bounded(history, scenario.planner.max_output_chars)}

Return a minimal AttackPlan. It must contain no more than
{scenario.planner.max_steps} steps and must make the machine verifier pass.
"""


def read_vulhub_documentation(vulhub_dir: Path) -> str:
    for name in ("README.md", "README.zh-cn.md"):
        path = vulhub_dir / name
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
    return "No local Vulhub README was found."


def validate_plan_policy(plan: AttackPlan, scenario: Scenario) -> None:
    if len(plan.steps) > scenario.planner.max_steps:
        raise PlannerError(
            f"plan has {len(plan.steps)} steps; limit is {scenario.planner.max_steps}"
        )
    banned = {
        "nmap",
        "masscan",
        "rustscan",
        "gobuster",
        "ffuf",
        "dirb",
        "hydra",
        "sqlmap",
        "metasploit",
        "msfconsole",
    }
    for step in plan.steps:
        executable = Path(step.argv[0]).name.lower()
        if executable in banned:
            raise PlannerError(f"out-of-scope executable in step {step.id}: {executable}")
        joined = "\n".join(step.argv)
        if "${TARGET_HOST}" not in joined and "${TARGET_PORT}" not in joined:
            raise PlannerError(f"step {step.id} does not reference the declared target")
        if "http://" in joined or "https://" in joined:
            # Literal public research URLs belong in planning, never execution.
            literals = [
                value
                for value in step.argv
                if ("http://" in value or "https://" in value)
                and "${TARGET_HOST}" not in value
            ]
            if literals:
                raise PlannerError(f"step {step.id} contains a literal URL")


def _extract_json(text: str) -> object:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[1].rsplit("```", 1)[0]
    return json.loads(stripped)


def _bounded(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated by T9-GPT]"
