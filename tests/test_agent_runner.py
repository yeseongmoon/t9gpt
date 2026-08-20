import json
from pathlib import Path

import agent_runner
from models import Scenario


def _scenario() -> Scenario:
    return Scenario.model_validate(
        {
            "t9_code": "T9-25-01-S-N-CL",
            "cve": "CVE-2023-50164",
            "name": "Apache Struts2 File Upload RCE",
            "software": "struts2",
            "lane": "network",
            "supported": True,
            "vulhub_path": "struts2/s2-066",
            "port": 8080,
            "http_path": "/",
            "tactics": "CL",
            "verification": [
                {"type": "any_step_output", "stdout_regex": "x"}
            ],
        }
    )


def test_task_prompt_carries_target_cve_and_token() -> None:
    prompt = agent_runner.build_task_prompt(
        _scenario(), "127.0.0.1", 8080, proof_token="T9PROOFabc123"
    )
    assert "127.0.0.1:8080" in prompt
    assert "CVE-2023-50164" in prompt
    assert "Initial Access" in prompt and "Command and Control" in prompt
    assert "T9PROOFabc123" in prompt


def test_system_prompt_enforces_scope() -> None:
    # The hard leash lives in the claude-loop system prompt.
    sp = agent_runner.CLAUDE_LOOP_SYSTEM_PROMPT.lower()
    assert "nmap" in sp and "gobuster" in sp
    assert "do not" in sp
    assert "confirmed present" in sp


def test_diversity_hint_is_appended() -> None:
    prompt = agent_runner.build_task_prompt(
        _scenario(), "127.0.0.1", 8080, proof_token="T9PROOFx",
        diversity_hint="Prefer a different payload.",
    )
    assert "Prefer a different payload." in prompt


class _FakePopen:
    """Minimal stand-in for subprocess.Popen for run_agent."""

    def __init__(self, lines: list[str]) -> None:
        self.stdout = iter(lines)
        self.pid = 4242
        self._rc = 0

    def wait(self, timeout: float | None = None) -> int:
        return self._rc

    def poll(self) -> int:
        return self._rc


def test_claude_loop_caps_budget_and_parses_result(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        return _FakePopen(
            [
                json.dumps({"type": "assistant", "message": {"content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": "curl ..."}}
                ]}}) + "\n",
                json.dumps({"type": "user", "message": {"content": [
                    {"type": "tool_result", "content": "T9PROOFdeadbeef"}
                ]}}) + "\n",
                # The agent's completion block — its self-reported labels + stop signal.
                json.dumps({"type": "assistant", "message": {"content": [
                    {"type": "text", "text":
                     'T9_RESULT\n{"technique_id":"ognl-echo","tool":"curl",'
                     '"payload_family":"OGNL","proof_obtained":true,'
                     '"exploit_script":"exploit.sh","notes":"done"}'}
                ]}}) + "\n",
                json.dumps({"type": "result", "subtype": "success",
                            "total_cost_usd": 0.042, "session_id": "s-1",
                            "result": "done T9PROOFdeadbeef"}) + "\n",
            ]
        )

    monkeypatch.setattr(agent_runner.subprocess, "Popen", fake_popen)

    scenario = _scenario()
    scenario.agent.budget_usd = 0.5
    tech = agent_runner.Technique(id="ognl-echo", name="OGNL echo", hint="h", mitre="T1190")
    result = agent_runner.run_agent(
        scenario,
        host="127.0.0.1",
        port=8080,
        work_dir=tmp_path / "work",
        transcript_path=tmp_path / "transcript.txt",
        proof_token="T9PROOFdeadbeef",
        technique=tech,
        model="claude-opus-4-8",
    )

    # The hard dollar cap and chosen model are passed to the CLI; only Bash is allowed.
    assert "--max-budget-usd" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--max-budget-usd") + 1] == "0.5"
    assert captured["cmd"][captured["cmd"].index("--model") + 1] == "claude-opus-4-8"
    assert "Bash" in captured["cmd"]
    assert "ANTHROPIC_API_KEY" not in captured["env"]
    # Result parsed from stream-json; proof token in tool output → agent claim.
    assert result.engine == "claude-loop"
    assert result.cost_usd == 0.042
    assert result.session_id == "s-1"
    assert result.agent_claimed_success is True
    assert result.model == "claude-opus-4-8"
    assert result.technique_id == "ognl-echo"
    # The T9_RESULT block is parsed into self-reported labels.
    assert result.result_label is not None
    assert result.result_label["technique_id"] == "ognl-echo"
    # A well-behaved agent stops itself → we do NOT force-kill, so cost/session
    # from the final result event are captured and stopped_on_proof is False.
    assert result.stopped_on_proof is False
    assert (tmp_path / "transcript.txt").is_file()


def test_claude_loop_kills_runaway_after_completion(tmp_path: Path, monkeypatch) -> None:
    """An agent that keeps using tools AFTER its completion block is force-stopped."""
    def fake_popen(cmd, **kwargs):
        return _FakePopen([
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "text", "text": 'T9_RESULT\n{"proof_obtained":true}'}
            ]}}) + "\n",
            # Runaway: more tool use after the completion block.
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "nmap ..."}}
            ]}}) + "\n",
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "more ..."}}
            ]}}) + "\n",
        ])

    monkeypatch.setattr(agent_runner.subprocess, "Popen", fake_popen)
    result = agent_runner.run_agent(
        _scenario(), host="127.0.0.1", port=8080,
        work_dir=tmp_path / "w", transcript_path=tmp_path / "t.txt",
        proof_token="T9PROOFx",
    )
    assert result.stopped_on_proof is True


def test_claude_loop_finds_exploit_script(tmp_path: Path, monkeypatch) -> None:
    """The reproduction script the agent writes is located and reported."""
    work = tmp_path / "work"

    def fake_popen(cmd, **kwargs):
        # Simulate the agent writing a repro script into its work dir.
        work.mkdir(parents=True, exist_ok=True)
        (work / "exploit.sh").write_text("#!/bin/sh\ncurl ...\n")
        return _FakePopen([
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "text", "text":
                 'T9_RESULT\n{"technique_id":"t","exploit_script":"exploit.sh","proof_obtained":true}'}
            ]}}) + "\n",
            json.dumps({"type": "result", "total_cost_usd": 0.01, "session_id": "s"}) + "\n",
        ])

    monkeypatch.setattr(agent_runner.subprocess, "Popen", fake_popen)
    scenario = _scenario()
    result = agent_runner.run_agent(
        scenario, host="127.0.0.1", port=8080,
        work_dir=work, transcript_path=tmp_path / "t.txt",
        proof_token="T9PROOFx",
    )
    assert result.exploit_script == "exploit.sh"


def test_benign_uses_benign_prompt(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakePopen([
            json.dumps({"type": "result", "total_cost_usd": 0.01, "session_id": "s"}) + "\n",
        ])

    monkeypatch.setattr(agent_runner.subprocess, "Popen", fake_popen)
    scenario = _scenario()
    agent_runner.run_agent(
        scenario, host="127.0.0.1", port=8080,
        work_dir=tmp_path / "w", transcript_path=tmp_path / "t.txt",
        proof_token="T9PROOFx", benign=True,
    )
    sp_index = captured["cmd"].index("--system-prompt") + 1
    assert captured["cmd"][sp_index] == agent_runner.BENIGN_SYSTEM_PROMPT


def test_result_block_parsing_edge_cases(tmp_path: Path) -> None:
    # Nested braces in a string field must not break balance tracking.
    t = tmp_path / "tr.txt"
    t.write_text('prose\nT9_RESULT\n{"notes":"used {curly} in payload","proof_obtained":false}\ntail')
    parsed = agent_runner._parse_result_block(t)
    assert parsed == {"notes": "used {curly} in payload", "proof_obtained": False}
    # No block → None.
    t.write_text("no result here")
    assert agent_runner._parse_result_block(t) is None
