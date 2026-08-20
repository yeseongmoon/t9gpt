"""Opt-in Docker integration test for isolation, relay, and tcpdump lifecycle."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import environment as environment_module
from models import AttackPlan, Scenario
from orchestrator import _execute_attempt

pytestmark = pytest.mark.skipif(
    os.environ.get("T9GPT_DOCKER_TEST") != "1",
    reason="set T9GPT_DOCKER_TEST=1 to run Docker integration tests",
)


def test_controlled_relay_and_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vulhub = tmp_path / "vulhub"
    compose_dir = vulhub / "demo" / "http"
    compose_dir.mkdir(parents=True)
    (compose_dir / "docker-compose.yml").write_text(
        """\
services:
  demo:
    image: python:3.12-slim-bookworm
    command: python -m http.server 8080
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(environment_module, "VULHUB_ROOT", vulhub)

    scenario = Scenario.model_validate(
        {
            "t9_code": "T9-25-99-S-N-CD",
            "name": "Pipeline fixture",
            "software": "demo",
            "lane": "network",
            "supported": True,
            "vulhub_path": "demo/http",
            "port": 8080,
            "tactics": "CD",
            "environment": {
                "path": "demo/http",
                "service": "demo",
                "target_port": 8080,
                "readiness": {"type": "http", "path": "/"},
            },
            "capture": {"mode": "clean", "ports": [8080]},
            "verification": [
                {"type": "any_step_output", "stdout_regex": "${PROOF_TOKEN}"}
            ],
        }
    )
    plan = AttackPlan.model_validate(
        {
            "summary": "request the fixture",
            "success_rationale": "a successful request prints the proof token",
            "files": [
                {
                    "path": "poc.py",
                    "content": (
                        "import sys,urllib.request\n"
                        "url=f'http://{sys.argv[1]}:{sys.argv[2]}/'\n"
                        "assert urllib.request.urlopen(url,timeout=10).status == 200\n"
                        "print(sys.argv[3])\n"
                    ),
                }
            ],
            "steps": [
                {
                    "id": "request",
                    "argv": [
                        "python",
                        "/work/poc.py",
                        "${TARGET_HOST}",
                        "${TARGET_PORT}",
                        "${PROOF_TOKEN}",
                    ],
                    "expected_evidence": "proof token after HTTP 200",
                }
            ],
        }
    )

    outcome = _execute_attempt(
        scenario=scenario,
        run_id="integration",
        proof_token="T9_integration",
        plan=plan,
        run_dir=tmp_path / "run",
        label="clean",
        capture=True,
    )
    assert outcome["verification"]["passed"]
    pcap = tmp_path / "run" / "clean.pcap"
    assert pcap.stat().st_size > 24
    if tshark := shutil.which("tshark"):
        decoded = subprocess.run(
            [
                tshark,
                "-r",
                str(pcap),
                "-T",
                "fields",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        rows = [line.split("\t") for line in decoded.stdout.splitlines() if line]
        assert rows
        assert all("8080" in ports for ports in rows)
