"""Network capture using a tcpdump sidecar in the target network namespace."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from pathlib import Path

from models import CaptureConfig

logger = logging.getLogger(__name__)


class CaptureError(RuntimeError):
    """Raised when a packet capture cannot be trusted as a dataset artifact."""


class PacketCapture:
    def __init__(
        self,
        name: str,
        target_container_id: str,
        peer_ip: str,
        output_path: Path,
        config: CaptureConfig,
        require_packets: bool = True,
        max_drop_fraction: float = 0.0,
    ) -> None:
        self.name = name
        self.target_container_id = target_container_id
        self.peer_ip = peer_ip
        self.output_path = output_path.resolve()
        self.config = config
        self.require_packets = require_packets
        # Deterministic mode wants a perfect capture (0.0 = any drop fails).
        # Long agent-mode captures tolerate a small kernel-drop fraction so a
        # few drops over many minutes don't discard an otherwise-good dataset.
        self.max_drop_fraction = max_drop_fraction
        self._started = False
        self._logs = ""

    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.touch()
        self.output_path.chmod(0o666)
        filter_expression = self._build_filter()
        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            self.name,
            "--network",
            f"container:{self.target_container_id}",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_RAW",
            "--cap-add",
            "NET_ADMIN",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--mount",
            f"type=bind,src={self.output_path},dst=/capture.pcap",
            self.config.image,
            "tcpdump",
            "--immediate-mode",
            "-U",
            "-n",
            "-i",
            "any",
            "-s",
            str(self.config.snaplen),
            "-w",
            "/capture.pcap",
            filter_expression,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise CaptureError(f"could not start tcpdump sidecar: {result.stderr.strip()}")
        self._started = True
        self._wait_until_listening()

    def stop(self) -> dict[str, object]:
        if not self._started:
            return {"path": str(self.output_path), "started": False}
        subprocess.run(
            ["docker", "kill", "--signal", "SIGINT", self.name],
            capture_output=True,
            text=True,
            check=False,
        )
        wait = subprocess.run(
            ["docker", "wait", self.name],
            capture_output=True,
            text=True,
            check=False,
        )
        logs = subprocess.run(
            ["docker", "logs", self.name],
            capture_output=True,
            text=True,
            check=False,
        )
        self._logs = (logs.stdout or "") + (logs.stderr or "")
        subprocess.run(
            ["docker", "rm", "-f", self.name],
            capture_output=True,
            text=True,
            check=False,
        )
        self._started = False
        self.output_path.chmod(0o644)

        dropped = _extract_stat(self._logs, "packets dropped by kernel")
        received = _extract_stat(self._logs, "packets received by filter")
        captured = _extract_stat(self._logs, "packets captured")
        metadata: dict[str, object] = {
            "path": str(self.output_path),
            "container_exit": wait.stdout.strip(),
            "packets_captured": captured,
            "packets_received": received,
            "packets_dropped": dropped,
            "filter": self._build_filter(),
            "peer_ip": self.peer_ip,
        }
        if dropped and dropped > 0:
            denominator = received or captured or 0
            fraction = dropped / denominator if denominator else 1.0
            metadata["drop_fraction"] = round(fraction, 4)
            if fraction > self.max_drop_fraction:
                raise CaptureError(
                    f"tcpdump dropped {dropped} packets "
                    f"({fraction:.1%} > tolerance {self.max_drop_fraction:.1%})"
                )
            logger.warning(
                "tcpdump dropped %d packets (%.2f%%) — within tolerance",
                dropped, fraction * 100,
            )
        empty = not self.output_path.is_file() or self.output_path.stat().st_size <= 24
        metadata["empty"] = empty
        if empty and self.require_packets:
            raise CaptureError(
                f"capture is missing or empty: {self.output_path}; "
                f"tcpdump logs: {self._logs.strip()[:1000]}"
            )
        metadata["size_bytes"] = self.output_path.stat().st_size
        if not empty:
            metadata.update(self._capinfos())
        return metadata

    def abort(self) -> None:
        subprocess.run(
            ["docker", "rm", "-f", self.name],
            capture_output=True,
            text=True,
            check=False,
        )
        self._started = False

    def _wait_until_listening(self) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            inspect = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", self.name],
                capture_output=True,
                text=True,
                check=False,
            )
            logs = subprocess.run(
                ["docker", "logs", self.name],
                capture_output=True,
                text=True,
                check=False,
            )
            output = (logs.stdout or "") + (logs.stderr or "")
            if "listening on" in output:
                return
            if inspect.returncode != 0 or inspect.stdout.strip() != "true":
                self.abort()
                raise CaptureError(f"tcpdump exited during startup: {output.strip()}")
            time.sleep(0.2)
        self.abort()
        raise CaptureError("tcpdump did not report readiness within 15 seconds")

    def _build_filter(self) -> str:
        # The sidecar shares the target container's network namespace, so its
        # interfaces already define the target boundary. Filtering on the relay
        # address is unreliable on Docker bridges that apply source NAT.
        pieces: list[str] = []
        if self.config.protocol != "any":
            pieces.append(self.config.protocol)
        if self.config.ports:
            ports = " or ".join(f"port {port}" for port in self.config.ports)
            pieces.append(f"({ports})")
        return " and ".join(pieces) if pieces else "ip or ip6"

    def _capinfos(self) -> dict[str, object]:
        capinfos = shutil.which("capinfos")
        if not capinfos:
            return {}
        result = subprocess.run(
            [capinfos, "-c", "-s", "-a", "-e", str(self.output_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise CaptureError(f"capinfos rejected {self.output_path}: {result.stderr.strip()}")
        return {"capinfos": result.stdout.strip()}


def _extract_stat(text: str, label: str) -> int | None:
    match = re.search(rf"(\d+)\s+{re.escape(label)}", text)
    return int(match.group(1)) if match else None


def token_in_http_responses(
    pcap_path: Path, token: str, server_port: int | None = None
) -> bool | None:
    """Ground-truth success check from the capture itself.

    Returns True only if the proof token appears in traffic the target sent
    *back* (server→client) — i.e. it actually executed the command and reflected
    the token. Matching is scoped to the server's source port, so the token
    inside the agent's own *request* (e.g. ``echo <token>`` in a header) cannot
    cause a false positive — which is why this is trustworthy where a transcript
    scan is not.

    It scans response-direction packet bytes rather than tshark's
    ``http.file_data`` field: that field is empty for bodies tshark classifies as
    ``media`` or chunked-without-content-type (exactly how Struts OGNL RCE
    responses come back), which would otherwise mislabel a genuine success as a
    failure.

    Returns None when it cannot be determined (no tshark, unreadable pcap, or no
    ``server_port`` to scope the response direction).
    """
    safe = re.sub(r"[^A-Za-z0-9]", "", token)
    tshark = shutil.which("tshark")
    if not safe or not tshark or not server_port:
        return None
    if not pcap_path.is_file() or pcap_path.stat().st_size <= 24:
        return None
    result = subprocess.run(
        [tshark, "-r", str(pcap_path),
         "-Y", f'tcp.srcport=={int(server_port)} and frame contains "{safe}"',
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())


def token_in_pcap_any(pcap_path: Path, token: str) -> bool | None:
    """Out-of-band proof oracle: is the token anywhere in the capture?

    Used for ``oob_callback`` exploits where success shows up as the *target*
    making an outbound request carrying the token (e.g. a JNDI/DNS callback)
    rather than reflecting it in an HTTP response. This is deliberately broad —
    it matches requests too — so it is the weakest oracle and only appropriate
    when the exploit class is inherently out-of-band.

    Returns None when it cannot be determined (no tshark, or unreadable pcap).
    """
    safe = re.sub(r"[^A-Za-z0-9]", "", token)
    tshark = shutil.which("tshark")
    if not safe or not tshark:
        return None
    if not pcap_path.is_file() or pcap_path.stat().st_size <= 24:
        return None
    # `frame contains` scans raw packet bytes for the ASCII needle.
    result = subprocess.run(
        [tshark, "-r", str(pcap_path), "-Y", f'frame contains "{safe}"',
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())
