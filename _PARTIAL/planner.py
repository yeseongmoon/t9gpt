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
