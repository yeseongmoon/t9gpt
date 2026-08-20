"""Vulhub target lifecycle for the bounded-agent ("diversity") run mode."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from models import Scenario

logger = logging.getLogger(__name__)

VULHUB_ROOT = Path(os.environ.get("VULHUB_ROOT", Path.home() / "vulhub"))


class EnvironmentError(RuntimeError):
    """Raised when Docker or Vulhub lifecycle management fails."""


class VulhubTarget:
    """Lean Vulhub lifecycle for the autonomous-agent ("diversity") mode.

    It does NOT build relay/runner isolation: the agent runs as a host process
    and reaches the target via its published port, so all we need is
    `compose up`, the target container id (for NDR capture in its netns), the
    host-published address, a readiness probe, and a thorough teardown.
    `down()` is idempotent and safe to call in a `finally` block.
    """

    @staticmethod
    def preflight() -> list[str]:
        """Report why the host can't run T9-GPT (missing docker/git, dead daemon)."""
        errors: list[str] = []
        for binary in ("docker", "git"):
            if not shutil.which(binary):
                errors.append(f"{binary} is not installed")
        if errors:
            return errors
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            errors.append(f"Docker daemon is unavailable: {result.stderr.strip()}")
        return errors

    def __init__(self, scenario: Scenario, run_id: str) -> None:
        if scenario.environment is None:
            raise EnvironmentError("scenario has no Vulhub environment")
        self.scenario = scenario
        self.config = scenario.environment
        code = re.sub(r"[^a-z0-9]", "", scenario.t9_code.lower())[-16:]
        safe_id = re.sub(r"[^a-z0-9]", "", run_id.lower())[-20:]
        self.project = f"t9agent{code}{safe_id}"[:50]
        self.compose_dir = (VULHUB_ROOT / self.config.path)
        self.target_container_id: str | None = None
        self.target_ip: str | None = None
        self.host = "127.0.0.1"
        self.port: int = self.config.target_port
        self._started = False

    def up(self) -> None:
        self._resolve_compose_dir()
        _run(self._compose_cmd("up", "-d"), cwd=self.compose_dir)
        self._started = True

        cid = _run(
            self._compose_cmd("ps", "-q", self.config.service),
            cwd=self.compose_dir,
        ).stdout.strip()
        if not cid:
            raise EnvironmentError(
                f"compose service '{self.config.service}' did not produce a container"
            )
        self.target_container_id = cid.splitlines()[0]
        self.target_ip = self._container_ip(self.target_container_id)
        self.port = self._published_port()
        self.wait_ready()

    def wait_ready(self) -> None:
        readiness = self.config.readiness
        deadline = time.monotonic() + readiness.timeout_seconds
        last_error = ""
        while time.monotonic() < deadline:
            try:
                if readiness.type == "tcp":
                    with socket.create_connection((self.host, self.port), timeout=3):
                        return
                else:
                    url = f"http://{self.host}:{self.port}{readiness.path}"
                    with urllib.request.urlopen(url, timeout=3) as response:
                        status = response.status
                        if readiness.expected_status is None or status == readiness.expected_status:
                            return
                        last_error = f"status {status}"
            except urllib.error.HTTPError as exc:
                # An HTTP error still proves the service is up and answering.
                if readiness.expected_status is None or exc.code == readiness.expected_status:
                    return
                last_error = f"status {exc.code}"
            except (OSError, urllib.error.URLError) as exc:
                last_error = str(exc)
            time.sleep(readiness.interval_seconds)
        raise EnvironmentError(
            f"target {self.host}:{self.port} not ready after "
            f"{readiness.timeout_seconds}s: {last_error[:300]}"
        )

    def down(self) -> None:
        """Tear everything down. Idempotent; never raises."""
        if self._started:
            subprocess.run(
                self._compose_cmd("down", "--volumes", "--remove-orphans"),
                cwd=self.compose_dir,
                capture_output=True,
                text=True,
                check=False,
            )
        self._started = False
        self.target_container_id = None

    def _published_port(self) -> int:
        """Resolve the host-published port for the target service.

        Vulhub usually maps host:container 1:1, but resolve it explicitly so a
        non-1:1 mapping still points the agent at the right host port. Falls
        back to the declared container port.
        """
        result = subprocess.run(
            self._compose_cmd("port", self.config.service, str(self.config.target_port)),
            cwd=self.compose_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        binding = result.stdout.strip().splitlines()
        if result.returncode == 0 and binding:
            # e.g. "0.0.0.0:8080" → 8080
            tail = binding[-1].rsplit(":", 1)
            if len(tail) == 2 and tail[1].isdigit():
                return int(tail[1])
        return self.config.target_port

    def _container_ip(self, container: str) -> str:
        raw = _run(["docker", "inspect", container]).stdout
        data = json.loads(raw)
        networks = data[0]["NetworkSettings"]["Networks"]
        for details in networks.values():
            address = details.get("IPAddress", "")
            if address:
                return address
        return ""

    def _resolve_compose_dir(self) -> None:
        if not VULHUB_ROOT.exists():
            raise EnvironmentError(
                f"Vulhub is not installed at {VULHUB_ROOT}; clone it before running T9-GPT"
            )
        root = VULHUB_ROOT.resolve()
        path = self.compose_dir.resolve()
        if not path.is_relative_to(root) or not path.is_dir():
            raise EnvironmentError(f"Vulhub environment not found: {path}")
        if not (path / "docker-compose.yml").exists() and not (path / "compose.yml").exists():
            raise EnvironmentError(f"no Compose file found in {path}")
        self.compose_dir = path

    def _compose_cmd(self, *args: str) -> list[str]:
        return ["docker", "compose", "-p", self.project, *args]


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise EnvironmentError(f"command failed ({' '.join(cmd)}): {detail[:2000]}")
    return result
