"""Bounded autonomous-agent execution against a live Vulhub target.

This is the "diversity" engine. Instead of replaying a fixed plan, an agent
attacks the already-running target so the collected logs vary run-to-run — but
it is *leashed* so runs stay on-theme and cheap.

The engine is a single ``claude -p`` session whose system prompt and tool set
we fully own. It is told the vulnerability is already confirmed (so it skips
recon), forbidden from scanning/enumerating, restricted to the Bash tool (plus
WebFetch/WebSearch only when web research is enabled), capped by
``--max-budget-usd`` (a hard dollar cap) and a wall-clock backstop, and
instructed to emit a proof token and stop the moment it lands the exploit. This
gives real scope enforcement and a measurable, tiny cost.

Tokens are spent only here.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from models import TACTIC_LETTER_NAMES, ProofSpec, Scenario, Technique

logger = logging.getLogger(__name__)

# The system prompt for the bounded claude-loop engine. This is the real leash —
# it replaces (not appends to) the default, so the agent has no pentest
# methodology of its own pulling it toward broad recon.
CLAUDE_LOOP_SYSTEM_PROMPT = """\
You are a precise red-team operator in an AUTHORIZED, fully isolated lab. A single
disposable Docker container hosts ONE known-vulnerable service. Your job is to
produce a clean, realistic exploitation of ONE specified CVE for a network
detection dataset — NOT to perform a penetration test.

HARD RULES (breaking any of these ruins the dataset):
- The vulnerability is CONFIRMED PRESENT. Do NOT fingerprint, version-check, or
  survey the service first. Go straight to exploiting the named CVE.
- NEVER run scanners or enumerators: no nmap, masscan, gobuster, dirb, ffuf,
  nikto, wpscan, sqlmap, hydra — no port scanning or directory/path brute-forcing
  of any kind.
- Touch ONLY the single target host:port you are given. Never probe other ports,
  other hosts, or unrelated URL paths.
- Do NOT establish persistence, add users, pivot, escalate, exfiltrate data, or
  run any denial-of-service.
- Keep it minimal: a handful of focused requests that actually carry out the
  exploit. Do not explore.

WHAT YOU MAY VARY (this is desired — it is the point of the exercise):
- The specific payload, encoding, tool, and request shape used to trigger the
  CVE. Your task names ONE technique to use — carry out that one.

COMPLETION PROTOCOL (do these in order, then STOP):
1. Exploit the CVE using the technique named in your task. Confirm success using
   the PROOF METHOD given in your task — that is what makes the proof token
   observable in ground-truth traffic/state, not merely in your own request.
2. Once proof is obtained, write a minimal standalone reproduction script to the
   EXACT absolute directory given in your task (the "Save the reproduction script"
   line), named `exploit.sh` (or `exploit.py` if Python is clearer). Use that
   absolute path verbatim — do NOT write it to your home directory or anywhere
   else. It targets ${TARGET_HOST}:${TARGET_PORT} (env vars or hardcoded), carries
   out THIS technique, and needs no scanning. It does NOT have to be portable or
   robust — a faithful, readable PoC is enough. Use a PLACEHOLDER where the live
   proof token would go, not the real token.
3. Print a final result block on its own, EXACTLY in this shape (one JSON object):
   T9_RESULT
   {"technique_id":"<id from task or a short slug>","injection_point":"<where the payload entered>","payload_family":"<e.g. OGNL, JNDI, deserialization>","tool":"<primary tool, e.g. curl>","proof_obtained":true,"exploit_script":"exploit.sh","notes":"<one line>"}
4. STOP immediately after the block. Do not continue, clean up, or explore.

If you cannot achieve execution within budget, print the same block with
"proof_obtained": false and stop. Never fall back to scanning or other vectors.

You have a Bash tool only. Work quickly and stop early.
"""

# Benign-mode leash: generate realistic *legitimate* traffic against the same
# service so the dataset gets hard negatives from the identical harness/target.
BENIGN_SYSTEM_PROMPT = """\
You are a normal administrator/user of a service in an AUTHORIZED lab. Your job
is to produce a short burst of ordinary, LEGITIMATE traffic against ONE service
for a network-detection dataset — this is a benign (non-attack) sample.

HARD RULES:
- Do NOT exploit anything, inject payloads, scan, enumerate, or probe for
  vulnerabilities. Behave like a legitimate client only.
- Touch ONLY the single target host:port you are given. No other hosts/ports.
- Use the ordinary features of the service (browse pages, call normal APIs,
  fetch static resources, submit well-formed benign requests).

COMPLETION PROTOCOL (then STOP):
1. Perform a handful of realistic, benign requests as described in your task.
2. Print a final result block on its own, EXACTLY in this shape:
   T9_RESULT
   {"technique_id":"benign","injection_point":null,"payload_family":null,"tool":"<primary tool>","proof_obtained":false,"exploit_script":null,"notes":"<one line describing the benign activity>"}
3. STOP immediately after the block.

You have a Bash tool only. Work quickly and stop early.
"""

# Appended to the claude-loop system prompt ONLY when web research is enabled for
# the scenario (references.allow_web). It grants external-knowledge tools while
# keeping the target-scope leash fully intact — research the CVE, not the target.
RESEARCH_ADDENDUM = """

RESEARCH AMENDMENT (this run only):
- TOOLS: in addition to Bash you ALSO have WebSearch and WebFetch. Use them to
  research THIS CVE — read the advisory, the fixing commit / patch diff, and public
  analysis — to understand and develop the exploit. Prefer the patch diff: it
  pinpoints the vulnerable sink and the guard that was added.
- Web access is for CVE KNOWLEDGE ONLY. Every rule above still holds: do NOT scan,
  fingerprint, or enumerate the TARGET; touch only the given target host:port; no
  persistence, pivot, or DoS.
- Research efficiently — a few targeted lookups, not broad browsing. Your budget
  cap still applies to the whole session.
"""


class AgentError(RuntimeError):
    """Raised when the bounded agent cannot be launched at all."""


@dataclass
class AgentRunResult:
    engine: str
    returncode: int
    timed_out: bool
    duration_seconds: float
    transcript_path: Path
    work_dir: Path
    cost_usd: float | None = None
    session_id: str | None = None
    # The agent's *self-reported* success (proof token seen in the transcript).
    # This is NOT authoritative — curl -v echoes the request, so the token can
    # appear here even on a failed exploit. Ground truth comes from the capture
    # (collector.token_in_http_responses / token_in_pcap_any) or the container
    # marker check in the orchestrator.
    agent_claimed_success: bool = False
    # The model actually used for this run (variation/escalation resolved).
    model: str | None = None
    # The technique this run was told to carry out (label provenance).
    technique_id: str | None = None
    # Parsed T9_RESULT block the agent emitted (self-reported labels).
    result_label: dict | None = None
    # Relative filename of the reproduction script the agent wrote, if any.
    exploit_script: str | None = None
    # True when we terminated the process the moment it signalled completion
    # (stop-on-proof) rather than letting it run to the budget/time cap.
    stopped_on_proof: bool = False


def _proof_instruction(proof: ProofSpec, proof_token: str) -> str:
    """The PROOF METHOD sentence — how the agent must make success observable in
    ground truth for the configured oracle."""
    if proof.type == "container_marker":
        return (
            f"PROOF METHOD: through the achieved execution, make the TARGET create a "
            f"file named exactly '{proof_token}' in '{proof.marker_dir}' on the target "
            f"host (e.g. run `touch {proof.marker_dir}/{proof_token}` via the RCE). "
            f"The file existing on the target is the proof — nothing needs to be reflected."
        )
    if proof.type == "oob_callback":
        return (
            f"PROOF METHOD: cause the TARGET to emit the exact string '{proof_token}' in "
            f"an outbound request it makes (an out-of-band callback). The token appearing "
            f"anywhere in captured traffic is the proof."
        )
    if proof.type == "container_log":
        return (
            f"PROOF METHOD: cause the exact string '{proof_token}' to be written into the "
            f"log file '{proof.log_path}' on the target — e.g. embed the token in a JNDI "
            f"lookup path so the failed lookup logs the payload. Its presence in that log "
            f"is the proof; nothing needs to be reflected back to you."
        )
    return (
        f"PROOF METHOD: make the target include the exact string '{proof_token}' in an "
        f"HTTP RESPONSE body (e.g. run `echo {proof_token}` through the achieved RCE so it "
        f"is echoed back in the response). Seeing it only in your own request does not count."
    )


def build_task_prompt(
    scenario: Scenario,
    host: str,
    port: int,
    proof_token: str,
    technique: Technique | None = None,
    proof: ProofSpec | None = None,
    avoid: list[str] | None = None,
    benign: bool = False,
    diversity_hint: str | None = None,
    work_dir: Path | None = None,
    reference_context: str | None = None,
) -> str:
    """The per-run task. Carries the target, CVE, technique, proof method, token.

    The hard constraints live in the system prompt; this stays focused on the
    specific job.
    """
    env = scenario.environment
    http_path = env.readiness.path if env else "/"

    if benign:
        profile = scenario.agent.benign_profile or (
            "browse the service like a normal user: fetch the main page and a few "
            "ordinary resources or well-formed API calls; nothing unusual."
        )
        lines = [
            f"Target service: {scenario.software} at {host}:{port}{http_path}.",
            f"Generate BENIGN, legitimate traffic only. {profile}",
            "Do not exploit, inject, scan, or probe. This is a benign (non-attack) sample.",
        ]
        if diversity_hint:
            lines.append(diversity_hint)
        return "\n".join(lines)

    cve = scenario.cve or "the named vulnerability"
    tactics = ", ".join(TACTIC_LETTER_NAMES.get(letter, letter) for letter in scenario.tactics)
    objective = scenario.agent.objective or (
        "achieve code execution (or equivalent impact) on the target"
    )
    proof = proof or scenario.agent.proof_for(technique)

    lines = [
        f"Target: {scenario.software} at {host}:{port}{http_path}.",
        f"Vulnerability to exploit: {cve} ({scenario.name}).",
        f"Objective: {objective}.",
        f"MITRE ATT&CK tactics to exercise: {tactics}.",
    ]
    if technique is not None:
        lines.append(f"Technique to use (id '{technique.id}'): {technique.name} — {technique.hint}")
        if technique.injection_point:
            lines.append(f"Injection point: {technique.injection_point}.")
        if technique.payload_family:
            lines.append(f"Payload family: {technique.payload_family}.")
        if technique.tool:
            lines.append(f"Suggested tool: {technique.tool}.")
    if reference_context:
        lines.append(
            "REFERENCE MATERIAL — you may not already know this CVE. Use the material "
            "below (analysis notes and/or the target's own source) to UNDERSTAND and "
            "DEVELOP the exploit, then VARY it for this run — do not copy it verbatim:"
        )
        lines.append(reference_context)
    lines.append(_proof_instruction(proof, proof_token))
    lines.append(f"Proof token (exact string): {proof_token}")
    if work_dir is not None:
        lines.append(
            "Save the reproduction script at this EXACT absolute path once you succeed: "
            f"{Path(work_dir).resolve()}/exploit.sh (this directory — not your home)."
        )
    if avoid:
        lines.append(
            "Recently-used techniques to avoid repeating if your assigned technique "
            f"gives you any choice: {', '.join(avoid)}."
        )
    for rule in scenario.agent.guardrails:
        lines.append(f"Additional constraint: {rule}")
    if diversity_hint:
        lines.append(diversity_hint)
    return "\n".join(lines)


def run_agent(
    scenario: Scenario,
    host: str,
    port: int,
    work_dir: Path,
    transcript_path: Path,
    proof_token: str,
    technique: Technique | None = None,
    proof: ProofSpec | None = None,
    model: str | None = None,
    avoid: list[str] | None = None,
    benign: bool = False,
    diversity_hint: str | None = None,
    reference_context: str | None = None,
) -> AgentRunResult:
    """Dispatch to the configured bounded-agent engine for ONE attempt."""
    work_dir.mkdir(parents=True, exist_ok=True)
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    proof = proof or scenario.agent.proof_for(technique)
    task = build_task_prompt(
        scenario, host, port, proof_token,
        technique=technique, proof=proof, avoid=avoid,
        benign=benign, diversity_hint=diversity_hint, work_dir=work_dir,
        reference_context=None if benign else reference_context,
    )
    model = model or scenario.agent.model or scenario.model
    # Web research tier (agentic-RAG slice 2): enabled per-scenario and never for
    # benign traffic. Grants WebFetch/WebSearch for CVE knowledge only.
    allow_web = bool(
        not benign
        and scenario.agent.references is not None
        and scenario.agent.references.allow_web
    )

    return _run_claude_loop(
        scenario, host, port, proof_token, task, work_dir, transcript_path,
        model=model, technique=technique, benign=benign, allow_web=allow_web,
    )


def _run_claude_loop(
    scenario: Scenario,
    host: str,
    port: int,
    proof_token: str,
    task: str,
    work_dir: Path,
    transcript_path: Path,
    model: str,
    technique: Technique | None = None,
    benign: bool = False,
    allow_web: bool = False,
) -> AgentRunResult:
    """A single bounded `claude -p` session we fully control."""
    if benign:
        system_prompt = BENIGN_SYSTEM_PROMPT
        allowed_tools = "Bash"
    else:
        system_prompt = CLAUDE_LOOP_SYSTEM_PROMPT + (RESEARCH_ADDENDUM if allow_web else "")
        allowed_tools = "Bash WebFetch WebSearch" if allow_web else "Bash"
    cmd = [
        "claude", "-p", task,
        "--system-prompt", system_prompt,
        "--allowed-tools", allowed_tools,
        "--permission-mode", "bypassPermissions",
        "--max-budget-usd", str(scenario.agent.budget_usd),
        "--model", model,
        "--output-format", "stream-json",
        "--verbose",
    ]
    env = os.environ.copy()
    # Use the operator's Claude subscription rather than an API key.
    env.pop("ANTHROPIC_API_KEY", None)

    logger.info(
        "Launching claude-loop (budget=$%.2f, model=%s, technique=%s%s%s) → http://%s:%d",
        scenario.agent.budget_usd, model,
        technique.id if technique else "-", ", benign" if benign else "",
        ", web" if allow_web else "", host, port,
    )

    # "completed" flips true when the agent prints the T9_RESULT sentinel; that
    # is the stop-on-proof signal — we terminate the moment it appears so we do
    # not burn the rest of the budget after the run is effectively done.
    state: dict[str, object] = {"cost": None, "session": None, "claimed": False,
                                "completed": False, "post_complete": False}

    def handle(line: str, transcript) -> None:
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        _render_claude_event(event, transcript, proof_token, state)

    returncode, timed_out, duration, stopped_early = _stream_subprocess(
        cmd, env=env, cwd=work_dir, transcript_path=transcript_path,
        header=f"# T9-GPT claude-loop transcript\n# target: http://{host}:{port}\n"
               f"# model: {model}\n# technique: {technique.id if technique else '-'}\n"
               f"# proof_token: {proof_token}\n\n",
        timeout_seconds=scenario.agent.timeout_seconds, line_handler=handle,
        # Force-terminate only a runaway agent: one that kept using tools AFTER
        # emitting its completion block. A well-behaved agent stops itself and we
        # let the session end naturally (so cost/session_id are captured).
        should_stop=lambda: bool(state["completed"]) and bool(state["post_complete"]),
    )
    result_label = _parse_result_block(transcript_path)
    exploit_script = _find_exploit_script(work_dir, result_label)
    logger.info(
        "claude-loop finished: rc=%s timed_out=%s stopped_on_proof=%s duration=%.1fs "
        "cost=%s claimed=%s script=%s",
        returncode, timed_out, stopped_early, duration,
        f"${state['cost']}" if state["cost"] is not None else "n/a",
        state["claimed"], exploit_script or "-",
    )
    return AgentRunResult(
        engine="claude-loop",
        returncode=returncode,
        timed_out=timed_out,
        duration_seconds=duration,
        transcript_path=transcript_path,
        work_dir=work_dir,
        cost_usd=state["cost"],  # type: ignore[arg-type]
        session_id=state["session"],  # type: ignore[arg-type]
        agent_claimed_success=bool(state["claimed"]),
        model=model,
        technique_id=technique.id if technique else None,
        result_label=result_label,
        exploit_script=exploit_script,
        stopped_on_proof=stopped_early,
    )


def _render_claude_event(event: dict, transcript, proof_token: str, state: dict) -> None:
    """Render one stream-json event into the readable transcript + harvest state."""
    etype = event.get("type")
    if etype == "assistant":
        for block in event.get("message", {}).get("content", []):
            if block.get("type") == "text":
                text = block.get("text", "")
                if text:
                    transcript.write(text + "\n")
                    if proof_token in text:
                        state["claimed"] = True
                    # The T9_RESULT sentinel is the agent's explicit "done" signal
                    # (emitted only after it wrote the exploit script).
                    if "T9_RESULT" in text:
                        state["completed"] = True
            elif block.get("type") == "tool_use":
                args = json.dumps(block.get("input", {}))[:2000]
                transcript.write(f"[TOOL] {block.get('name')}: {args}\n")
                # Tool activity AFTER the completion block = a runaway agent that
                # ignored the stop instruction → trip stop-on-proof to save budget.
                if state.get("completed"):
                    state["post_complete"] = True
    elif etype == "user":
        for block in event.get("message", {}).get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_result":
                content = block.get("content", "")
                if isinstance(content, list):
                    content = " ".join(
                        c.get("text", "") for c in content if isinstance(c, dict)
                    )
                snippet = str(content)[:2000]
                transcript.write(f"[RESULT] {snippet}\n")
                if proof_token in snippet:
                    state["claimed"] = True
                if state.get("completed"):
                    state["post_complete"] = True
    elif etype == "result":
        if event.get("total_cost_usd") is not None:
            state["cost"] = float(event["total_cost_usd"])
        state["session"] = event.get("session_id")
        final = str(event.get("result", ""))
        if proof_token in final:
            state["claimed"] = True
        if "T9_RESULT" in final:
            state["completed"] = True
    transcript.flush()


_EXPLOIT_NAMES = ("exploit.sh", "exploit.py", "exploit.rb", "exploit.js", "exploit.txt")


def _parse_result_block(transcript_path: Path) -> dict | None:
    """Extract the last ``T9_RESULT {json}`` block the agent emitted, if any."""
    try:
        text = transcript_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    idx = text.rfind("T9_RESULT")
    if idx == -1:
        return None
    return _extract_json_object(text[idx + len("T9_RESULT"):])


def _extract_json_object(text: str) -> dict | None:
    """Parse the first balanced ``{...}`` JSON object in ``text``."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    return None
                return obj if isinstance(obj, dict) else None
    return None


def _find_exploit_script(work_dir: Path, result_label: dict | None) -> str | None:
    """Locate the reproduction script the agent wrote in its work dir.

    Prefers the filename the agent named in its T9_RESULT block, then a small set
    of conventional names, then any ``exploit.*`` file. Path-guarded so a reported
    name cannot point outside the work dir.
    """
    root = work_dir.resolve()
    if result_label:
        named = result_label.get("exploit_script")
        if isinstance(named, str) and named:
            candidate = (work_dir / named).resolve()
            try:
                if candidate.is_file() and candidate.is_relative_to(root):
                    return candidate.relative_to(root).as_posix()
            except (OSError, ValueError):
                pass
    for name in _EXPLOIT_NAMES:
        if (work_dir / name).is_file():
            return name
    for path in sorted(work_dir.glob("exploit.*")):
        if path.is_file():
            return path.name
    return None


def _stream_subprocess(
    cmd: list[str],
    env: dict[str, str],
    cwd: Path,
    transcript_path: Path,
    header: str,
    timeout_seconds: int,
    line_handler,
    should_stop=None,
    launch_error: str = "could not launch agent",
) -> tuple[int, bool, float, bool]:
    """Run cmd, stream stdout through line_handler into the transcript.

    Terminates the process group on timeout, or early when ``should_stop()``
    returns True (stop-on-proof). Returns
    ``(returncode, timed_out, duration, stopped_early)``.
    """
    started = time.monotonic()
    timed_out = False
    stopped_early = False
    with transcript_path.open("w", encoding="utf-8") as transcript:
        transcript.write(header)
        transcript.flush()
        try:
            proc = subprocess.Popen(
                cmd, cwd=cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, start_new_session=True,
            )
        except OSError as exc:
            raise AgentError(f"{launch_error}: {exc}") from exc

        deadline = started + timeout_seconds
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line_handler(line, transcript)
                if should_stop is not None and should_stop():
                    stopped_early = True
                    _terminate_group(proc)
                    transcript.write(
                        "\n# [T9-GPT] completion signal seen — stopping early "
                        "(stop-on-proof)\n"
                    )
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    _terminate_group(proc)
                    transcript.write("\n# [T9-GPT] agent timed out — terminated\n")
                    break
            returncode = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_group(proc)
            returncode = proc.wait()
        except KeyboardInterrupt:
            _terminate_group(proc)
            raise
    return returncode, timed_out, time.monotonic() - started, stopped_early


def _terminate_group(proc: subprocess.Popen) -> None:
    """SIGTERM then SIGKILL the agent's whole process group."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
