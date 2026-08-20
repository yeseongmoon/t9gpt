"""Validated public models for T9 scenario catalogs and attack plans."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

T9_CODE_RE = re.compile(r"^T9-\d{2}-\d{2}-[SM]-(?:N|E|NE)-[A-N]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

# MITRE ATT&CK tactic letter → full name (per t9project.dev naming convention).
TACTIC_LETTER_NAMES = {
    "A": "Reconnaissance",
    "B": "Resource Development",
    "C": "Initial Access",
    "D": "Execution",
    "E": "Persistence",
    "F": "Privilege Escalation",
    "G": "Defense Evasion",
    "H": "Credential Access",
    "I": "Discovery",
    "J": "Lateral Movement",
    "K": "Collection",
    "L": "Command and Control",
    "M": "Exfiltration",
    "N": "Impact",
}

DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_BUDGET_USD = 1.0

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class ReadinessConfig(BaseModel):
    type: Literal["http", "tcp"] = "http"
    path: str = "/"
    expected_status: int | None = Field(default=None, ge=100, le=599)
    timeout_seconds: int = Field(default=90, ge=1, le=600)
    interval_seconds: float = Field(default=1.0, gt=0, le=30)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("readiness.path must start with '/'")
        return value


class EnvironmentConfig(BaseModel):
    type: Literal["vulhub"] = "vulhub"
    path: NonEmptyStr
    service: NonEmptyStr
    target_port: int = Field(gt=0, le=65535)
    readiness: ReadinessConfig = Field(default_factory=ReadinessConfig)

    @field_validator("path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("environment.path must stay under the Vulhub root")
        return value

    @field_validator("service")
    @classmethod
    def validate_service(cls, value: str) -> str:
        if not SAFE_NAME_RE.fullmatch(value):
            raise ValueError("environment.service contains unsafe characters")
        return value


class CaptureConfig(BaseModel):
    mode: Literal["raw", "clean", "both"] = "both"
    protocol: Literal["tcp", "udp", "any"] = "tcp"
    ports: list[int] = Field(default_factory=list, max_length=32)
    image: NonEmptyStr = "nicolaka/netshoot:v0.13"
    snaplen: int = Field(default=0, ge=0, le=262_144)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("capture ports must be between 1 and 65535")
        return list(dict.fromkeys(values))


class RunnerConfig(BaseModel):
    image: NonEmptyStr = "python:3.12-slim-bookworm"
    memory: NonEmptyStr = "512m"
    cpus: float = Field(default=1.0, gt=0, le=8)
    pids_limit: int = Field(default=128, ge=16, le=4096)
    step_timeout_seconds: int = Field(default=45, ge=1, le=600)


class ProofSpec(BaseModel):
    """How a successful exploit is proven from GROUND TRUTH, never the transcript.

    - ``reflected_http`` — the proof token appears in an HTTP *response* body in
      the capture (the target executed the command and echoed it back). Good for
      reflected RCE; verified by ``collector.token_in_http_responses``.
    - ``container_marker`` — the exploit makes the TARGET write a file named after
      the proof token under ``marker_dir``; verified with ``docker exec test -f``.
      This is the oracle for *blind* RCE where nothing is reflected.
    - ``oob_callback`` — the proof token appears anywhere in the capture (e.g. the
      target makes an outbound request carrying it); verified by
      ``collector.token_in_pcap_any``. Weakest oracle — use only when the exploit
      class is inherently out-of-band.
    - ``container_log`` — the proof token appears in a log file inside the TARGET
      container (e.g. Log4Shell: a failed JNDI lookup logs the token-bearing
      payload); verified with ``docker exec grep``. The oracle for exploits whose
      only ground-truth trace is a server-side log line.
    """

    type: Literal[
        "reflected_http", "container_marker", "oob_callback", "container_log"
    ] = "reflected_http"
    # container_marker only: absolute directory the token-named marker lands in.
    marker_dir: str = "/tmp"
    # container_log only: absolute path of the target-side log file to grep.
    log_path: str | None = None

    @field_validator("marker_dir")
    @classmethod
    def validate_marker_dir(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("proof.marker_dir must be an absolute path")
        return value.rstrip("/") or "/"

    @field_validator("log_path")
    @classmethod
    def validate_log_path(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("/"):
            raise ValueError("proof.log_path must be an absolute path")
        return value

    @model_validator(mode="after")
    def require_log_path(self) -> ProofSpec:
        if self.type == "container_log" and not self.log_path:
            raise ValueError("container_log proof requires log_path")
        return self


class Technique(BaseModel):
    """One distinct way to exploit the scenario's CVE.

    The agent carries out exactly ONE technique per run; sampling a different
    technique each run is what makes the collected logs diverse while staying
    on-theme (same CVE, same target). The fields other than ``hint`` are also
    the ground-truth labels attached to the resulting sample.
    """

    id: NonEmptyStr
    name: NonEmptyStr
    # The concrete instruction handed to the agent ("inject via the
    # Content-Type header using the Jakarta multipart parser", etc.).
    hint: NonEmptyStr
    mitre: str | None = None
    injection_point: str | None = None
    payload_family: str | None = None
    tool: str | None = None
    # Optional per-technique proof oracle override (else AgentConfig.proof).
    proof: ProofSpec | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not SAFE_NAME_RE.fullmatch(value):
            raise ValueError("technique id contains unsafe characters")
        return value

    @field_validator("mitre")
    @classmethod
    def validate_mitre(cls, value: str | None) -> str | None:
        if value and not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
            raise ValueError("mitre must look like T1190 or T1505.003")
        return value


class BaselinePoc(BaseModel):
    """A no-LLM canonical exploit run BEFORE the agent to confirm the target is
    genuinely vulnerable.

    Lets the orchestrator distinguish "the agent failed" from "the target was
    broken" *without spending a single token*. ``${HOST}``, ``${PORT}`` and
    ``${TOKEN}`` are expanded in each argv element; the command runs on the host.
    """

    command: list[NonEmptyStr] = Field(min_length=1, max_length=40)
    proof: ProofSpec = Field(default_factory=ProofSpec)
    timeout_seconds: int = Field(default=30, ge=1, le=300)


class ReferenceConfig(BaseModel):
    """Context-injection material for CVEs the model may not already know.

    The OFFLINE tier (``notes`` + ``source_paths``) needs no internet: freeform
    analysis text, plus source files the harness reads out of the TARGET
    container and folds into the agent's task. This lets the agent *develop* an
    exploit from primary sources (advisory text, the vulnerable code itself)
    instead of only recalling a known PoC — then vary it for diversity.

    ``advisory_urls``/``patch_urls`` + ``allow_web`` are pointers for a later
    web-enabled retrieval tier; in the offline tier the URLs are surfaced to the
    agent as references only, not fetched.
    """

    # Freeform advisory/analysis text pasted by the human (offline, actionable).
    notes: str | None = Field(default=None, max_length=20_000)
    # Absolute paths of files INSIDE the target container to read and inject
    # (e.g. the vulnerable class). The harness reads them via `docker exec`.
    source_paths: list[str] = Field(default_factory=list, max_length=12)
    # Pointers fetched only when allow_web (slice 2); listed as references offline.
    advisory_urls: list[str] = Field(default_factory=list, max_length=20)
    patch_urls: list[str] = Field(default_factory=list, max_length=20)
    # Slice 2: enable WebFetch/WebSearch retrieval tools for this scenario.
    allow_web: bool = False

    @field_validator("source_paths")
    @classmethod
    def validate_source_paths(cls, values: list[str]) -> list[str]:
        for path in values:
            if not path.startswith("/"):
                raise ValueError(
                    "references.source_paths entries must be absolute container paths"
                )
        return values

    def is_empty(self) -> bool:
        return not (self.notes or self.source_paths or self.advisory_urls or self.patch_urls)


class AgentConfig(BaseModel):
    """Bounds for the autonomous-agent ("diversity") run mode.

    The agent is free to choose *how* it exploits the target (this is what makes
    the collected logs diverse), but the scenario leashes it to one target, one
    CVE, and a hard dollar/time budget so runs stay on-theme and cheap.
    """

    # The engine is a single bounded `claude -p` session whose system prompt and
    # tool set WE control (real scope enforcement, hard $ cap).
    # Hard per-run dollar cap — the primary token-control lever
    # (passed to `claude --max-budget-usd`).
    budget_usd: float = Field(default=0.5, gt=0, le=100)
    # The core objective the agent should reach and then STOP at.
    objective: str | None = None
    # Extra "do not" constraints appended to the leash instruction.
    guardrails: list[str] = Field(default_factory=list)
    # Per-run wall-clock backstop for the whole agent session.
    timeout_seconds: int = Field(default=600, ge=30, le=7200)
    # Optional model override; falls back to the scenario's top-level model.
    model: str | None = None

    # --- Tier 1: diversity engine -------------------------------------------
    # Distinct exploitation techniques for this CVE. Sampling a different one per
    # run is the primary diversity lever (and provides free ground-truth labels).
    techniques: list[Technique] = Field(default_factory=list)
    # Model-variation pool: the run index picks one so run-to-run command styles
    # differ even for the same technique. Ignored when ``model`` is set.
    models: list[str] = Field(default_factory=list)

    # --- Tier 2: verified output --------------------------------------------
    # Default proof oracle (a technique may override with its own ProofSpec).
    proof: ProofSpec = Field(default_factory=ProofSpec)
    # Require the agent to write a reproducible exploit script on success.
    require_exploit_script: bool = True

    # --- Tier 3: don't pay to fail ------------------------------------------
    # Optional canonical PoC run (no LLM) before the agent to prove the target
    # is actually exploitable; a failure short-circuits the run token-free.
    baseline: BaselinePoc | None = None
    # Technique-cycling retries within one target lifecycle: on an unconfirmed
    # attempt, try the next technique (bounded by this and the bank size).
    max_attempts: int = Field(default=1, ge=1, le=10)
    # On each retry, advance the model-variation pool (cheap capability escalation).
    retry_escalates_model: bool = False

    # --- Tier 4: benign hard-negatives --------------------------------------
    # When set, the agent generates legit-looking traffic instead of an exploit,
    # yielding a labelled benign sample from the identical harness/target.
    benign_profile: str | None = None

    # --- Context injection (agentic-RAG, slice 1: offline) ------------------
    # Reference material for CVEs the model may not already know. The harness
    # resolves it (notes + source read from the target) and injects it into the
    # agent's task so it can develop the exploit rather than only recall it.
    references: ReferenceConfig | None = None

    def technique_order(
        self, run_index: int, avoid: list[str] | None = None
    ) -> list[Technique]:
        """Ordered techniques to try this run.

        Rotated by ``run_index`` so different runs lead with different techniques
        (diversity), with recently-used ids (``avoid``) pushed to the back
        (anti-repetition). Empty when the scenario declares no technique bank.
        """
        if not self.techniques:
            return []
        avoid = avoid or []
        n = len(self.techniques)
        rotated = [self.techniques[(run_index + i) % n] for i in range(n)]
        fresh = [t for t in rotated if t.id not in avoid]
        stale = [t for t in rotated if t.id in avoid]
        return fresh + stale

    def pick_model(self, run_index: int, fallback: str) -> str:
        """Model for this run: explicit override → variation pool → fallback."""
        if self.model:
            return self.model
        if self.models:
            return self.models[run_index % len(self.models)]
        return fallback

    def proof_for(self, technique: Technique | None) -> ProofSpec:
        """The proof oracle for a technique (its override, else the default)."""
        if technique is not None and technique.proof is not None:
            return technique.proof
        return self.proof


class Scenario(BaseModel):
    """Versioned scenario model with migration from the original flat JSON."""

    schema_version: int = Field(default=2, ge=1, le=2)
    t9_code: NonEmptyStr
    cve: str | None = None
    name: NonEmptyStr
    software: NonEmptyStr
    lane: Literal["network", "endpoint", "multi"]
    supported: bool = True
    tactics: NonEmptyStr
    note: str | None = None

    environment: EnvironmentConfig | None = None
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    runner: RunnerConfig = Field(default_factory=RunnerConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)

    # Original fields remain accepted and serialized for catalog compatibility.
    vulhub_path: str = ""
    port: int = Field(default=0, ge=0, le=65535)
    http_path: str = "/"
    budget_usd: float = Field(default=DEFAULT_BUDGET_USD, gt=0, le=1000)
    timeout_seconds: int = Field(default=DEFAULT_TIMEOUT_SECONDS, ge=10, le=3600)
    model: str = DEFAULT_MODEL

    @model_validator(mode="before")
    @classmethod
    def migrate_flat_fields(cls, raw: object) -> object:
        if not isinstance(raw, dict):
            return raw
        data = dict(raw)
        if "environment" not in data and data.get("supported") and data.get("vulhub_path"):
            data["environment"] = {
                "type": "vulhub",
                "path": data["vulhub_path"],
                "service": data.get("software", "target"),
                "target_port": data.get("port", 0),
                "readiness": {
                    "type": "http",
                    "path": data.get("http_path", "/"),
                },
            }
        if "capture" not in data:
            port = data.get("port", 0)
            data["capture"] = {"mode": "both", "ports": [port] if port else []}
        return data

    @model_validator(mode="after")
    def synchronize_legacy_fields(self) -> Scenario:
        if self.environment:
            self.vulhub_path = self.environment.path
            self.port = self.environment.target_port
            self.http_path = self.environment.readiness.path
        if not self.capture.ports and self.port:
            self.capture.ports = [self.port]
        return self

    @field_validator("t9_code")
    @classmethod
    def validate_t9_code(cls, value: str) -> str:
        if not T9_CODE_RE.fullmatch(value):
            raise ValueError("invalid T9 code format")
        return value

    @field_validator("tactics")
    @classmethod
    def validate_tactics(cls, value: str) -> str:
        if not value or any(letter < "A" or letter > "N" for letter in value):
            raise ValueError("tactics must contain only T9 tactic letters A-N")
        return value

    def agent_runnable_errors(self) -> list[str]:
        """Runnability for the autonomous-agent ("diversity") run mode.

        The agent's behaviour is labelled post-run from a ground-truth proof
        oracle rather than gated on a fixed machine verifier. A runnable
        scenario needs a live Vulhub target to attack and at least one network
        capture port to collect NDR traffic from.
        """
        errors: list[str] = []
        if self.lane not in ("network", "multi"):
            errors.append("agent mode (phase 1) supports network/multi scenarios only")
        if not self.supported or self.environment is None:
            errors.append("agent mode requires a supported Vulhub environment")
        if not self.capture.ports:
            errors.append("at least one capture port is required")
        if self.capture.protocol != "tcp":
            errors.append("phase 1 NDR capture supports TCP only")
        return errors

    def output_directory(self, base_dir: Path, run_id: str) -> Path:
        root = base_dir.resolve()
        output = (root / self.t9_code / "runs" / run_id).resolve()
        if not output.is_relative_to(root):
            raise ValueError("scenario output escapes the project directory")
        return output


