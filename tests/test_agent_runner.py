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