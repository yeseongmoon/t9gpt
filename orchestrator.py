#!/usr/bin/env python3
"""T9-GPT bounded-agent attack-traffic dataset generator CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import secrets
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from pyfiglet import Figlet
from rich import print
from rich.table import Table
from rich.text import Text

from agent_runner import AgentError, AgentRunResult, run_agent
from collector import (
    CaptureError,
    PacketCapture,
    token_in_http_responses,
    token_in_pcap_any,
)
from environment import EnvironmentError, VULHUB_ROOT, VulhubTarget
from models import (
    TACTIC_LETTER_NAMES,
    ProofSpec,
    ReferenceConfig,
    Scenario,
    Technique,
)

BASE_DIR = Path(__file__).parent.parent

TACTIC_MAP = TACTIC_LETTER_NAMES

logger = logging.getLogger(__name__)
logging.basicConfig(format="%(asctime)s %(levelname)s - %(message)s", level=logging.INFO)


class RunError(RuntimeError):
    """A controlled run failure that should be reported in the manifest."""


def load_scenarios(path: str | Path) -> list[Scenario]:
    catalog_path = Path(path)
    with catalog_path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    items = raw if isinstance(raw, list) else [raw]
    scenarios = [Scenario.model_validate(item) for item in items]
    codes = [scenario.t9_code for scenario in scenarios]
    duplicates = sorted({code for code in codes if codes.count(code) > 1})
    if duplicates:
        raise ValueError(f"duplicate T9 codes: {', '.join(duplicates)}")
    return scenarios


def select_scenario(scenarios: list[Scenario], t9_code: str | None) -> Scenario:
    if t9_code is None and len(scenarios) == 1:
        return scenarios[0]
    for scenario in scenarios:
        if scenario.t9_code == t9_code:
            return scenario
    available = ", ".join(scenario.t9_code for scenario in scenarios)
    raise ValueError(f"T9 code '{t9_code}' not found; available: {available}")


def validate_catalog(scenarios: list[Scenario]) -> list[tuple[Scenario, list[str]]]:
    return [(scenario, scenario.agent_runnable_errors()) for scenario in scenarios]


def run_agent_scenario(
    scenario: Scenario,
    output_root: Path = BASE_DIR,
    diversity_hint: str | None = None,
    run_index: int = 0,
    benign: bool = False,
    technique_id: str | None = None,
) -> Path:
    """Bounded-agent ("diversity") run: up → [baseline] → capture+agent (×N) → teardown.

    Tokens are spent only inside `run_agent`. One target lifecycle hosts up to
    ``agent.max_attempts`` technique-cycling attempts, each with its own capture
    and its own ground-truth proof check. Everything is torn down in `finally`
    so a run leaves no containers, networks, or volumes behind.
    """
    errors = scenario.agent_runnable_errors()
    if errors:
        raise RunError("; ".join(errors))
    preflight_errors = VulhubTarget.preflight()
    if preflight_errors:
        raise RunError("; ".join(preflight_errors))

    run_id = datetime.now().strftime("%Y%m%dT%H%M%S_%f") + "_" + secrets.token_hex(3)
    run_dir = scenario.output_directory(output_root, run_id)
    run_dir.mkdir(parents=True)
    _write_json(run_dir / "scenario.json", scenario.model_dump(mode="json"))

    # Anti-repetition: what did recent runs of this scenario already do?
    recent = _recent_techniques(scenario, output_root)
    order = _plan_techniques(scenario, run_index, technique_id, recent, benign)
    max_attempts = 1 if benign else min(scenario.agent.max_attempts, max(1, len(order)))

    manifest: dict[str, Any] = {
        "schema_version": 2,
        "mode": "benign" if benign else "agent",
        "run_id": run_id,
        "run_index": run_index,
        "t9_code": scenario.t9_code,
        "status": "running",
        "started_at": datetime.now().astimezone().isoformat(),
        "engine": "claude-loop",
        "budget_usd": scenario.agent.budget_usd,
        "capture_mode": scenario.capture.mode,
        "tactics": [
            {"letter": letter, "name": TACTIC_MAP[letter]} for letter in scenario.tactics
        ],
        "recent_techniques_avoided": recent,
        "planned_techniques": [t.id for t in order],
        "attempts": [],
        "agent": None,
        "capture": None,
    }
    _write_json(run_dir / "manifest.json", manifest)

    target = VulhubTarget(scenario, run_id)
    capture: PacketCapture | None = None
    capture_started = False
    try:
        logger.info("Starting Vulhub target: %s", scenario.environment.path)  # type: ignore[union-attr]
        target.up()
        if not target.target_container_id:
            raise RunError("target container is unavailable")
        manifest["target"] = {
            "vulhub_path": scenario.environment.path,  # type: ignore[union-attr]
            "host": target.host,
            "port": target.port,
            "container_ip": target.target_ip or "",
            "vulhub_commit": _vulhub_commit(),
        }
        _write_json(run_dir / "manifest.json", manifest)

        # --- Context injection (agentic-RAG slice 1). Resolve reference material
        # ONCE (notes + source read from the target) and inject it into every
        # attempt so the agent can develop an exploit it may not already know.
        reference_context, reference_record = (
            (None, None) if benign else _build_reference_context(scenario, target)
        )
        if reference_record is not None:
            manifest["references_used"] = reference_record
            _write_json(run_dir / "manifest.json", manifest)

        # --- Tier 3: baseline preflight. Prove the target is genuinely
        # exploitable with a no-LLM canonical PoC; if not, stop before the agent
        # runs so we never pay tokens to fail against a broken container.
        if not benign and scenario.agent.baseline is not None:
            baseline = _run_baseline(scenario, target, run_dir)
            manifest["baseline"] = baseline
            _write_json(run_dir / "manifest.json", manifest)
            if not baseline.get("confirmed"):
                manifest["status"] = "target_unexploitable"
                manifest["exploit_confirmed"] = False
                manifest["finished_at"] = datetime.now().astimezone().isoformat()
                _write_json(run_dir / "manifest.json", manifest)
                _write_checksums(run_dir)
                logger.warning(
                    "baseline PoC did not confirm exploitability — skipping agent "
                    "(no tokens spent): %s", run_dir,
                )
                return run_dir

        # --- Tier 1/3: technique-cycling attempts within one target lifecycle.
        attempt_records: list[dict[str, Any]] = []
        primary_result: AgentRunResult | None = None
        primary_adir: Path | None = None
        primary_record: dict[str, Any] | None = None
        confirmed_any = False

        for attempt_idx in range(max_attempts):
            technique = order[attempt_idx] if (order and not benign) else None
            proof = ProofSpec() if benign else scenario.agent.proof_for(technique)
            model = _attempt_model(scenario, run_index, attempt_idx)
            proof_token = "T9PROOF" + secrets.token_hex(8)
            adir = run_dir / "attempts" / f"a{attempt_idx:02d}"
            pcap_path = adir / "capture.pcap"

            capture = PacketCapture(
                f"{target.project}_cap{attempt_idx}"[:63],
                target.target_container_id,
                target.target_ip or target.host,
                pcap_path,
                scenario.capture,
                require_packets=False,
                max_drop_fraction=0.02,
            )
            capture.start()
            capture_started = True

            result = run_agent(
                scenario,
                host=target.host,
                port=target.port,
                work_dir=adir / "work",
                transcript_path=adir / "transcript.txt",
                proof_token=proof_token,
                technique=technique,
                proof=proof,
                model=model,
                avoid=recent,
                benign=benign,
                diversity_hint=diversity_hint,
                reference_context=reference_context,
            )
            capture_meta = capture.stop()
            capture_started = False

            # Authoritative label from ground truth (never the transcript).
            confirmed = None if benign else _check_proof(
                proof, pcap_path, proof_token, target.target_container_id,
                scenario.environment.target_port,  # type: ignore[union-attr]
            )
            record: dict[str, Any] = {
                "index": attempt_idx,
                "technique_id": technique.id if technique else None,
                "model": model,
                "proof_token": proof_token,
                "proof_method": proof.type,
                "exploit_confirmed": confirmed,
                "agent_claimed_success": result.agent_claimed_success,
                "stopped_on_proof": result.stopped_on_proof,
                "timed_out": result.timed_out,
                "cost_usd": result.cost_usd,
                "duration_seconds": round(result.duration_seconds, 2),
                "result_label": result.result_label,
                "capture": capture_meta,
                "pcap": str(pcap_path.relative_to(run_dir)),
                "transcript": str((adir / "transcript.txt").relative_to(run_dir)),
            }
            attempt_records.append(record)
            # Last attempt is the fallback primary; a confirmed attempt wins.
            primary_result, primary_adir, primary_record = result, adir, record
            manifest["attempts"] = attempt_records
            _write_json(run_dir / "manifest.json", manifest)

            if confirmed is True:
                confirmed_any = True
                break
            if not benign and attempt_idx + 1 < max_attempts:
                logger.info(
                    "attempt %d unconfirmed (technique=%s) — retrying next technique",
                    attempt_idx, record["technique_id"],
                )

        # Promote the labelled attempt's artifacts to the run root (back-compat
        # + convenience); the other attempts stay under attempts/.
        exploit_rel: str | None = None
        if primary_adir is not None:
            _promote(primary_adir / "capture.pcap", run_dir / "capture.pcap")
            _promote(primary_adir / "transcript.txt", run_dir / "agent_transcript.txt")
        if primary_result is not None and primary_result.exploit_script:
            src = (primary_adir / "work" / primary_result.exploit_script) if primary_adir else None
            if src is not None and src.is_file():
                dst = run_dir / Path(primary_result.exploit_script).name
                _promote(src, dst)
                exploit_rel = dst.name

        confirmed = primary_record["exploit_confirmed"] if primary_record else None
        technique = _technique_by_id(scenario, primary_record["technique_id"]) if primary_record else None

        manifest["agent"] = _agent_block(primary_result, exploit_rel) if primary_result else None
        manifest["capture"] = primary_record["capture"] if primary_record else None
        manifest["exploit_confirmed"] = confirmed
        manifest["label"] = {
            "kind": "benign" if benign else "attack",
            "exploit_confirmed": confirmed,
            "method": primary_record["proof_method"] if primary_record else None,
            "confirmed_in_attempt": primary_record["index"] if confirmed_any else None,
            "attempts": len(attempt_records),
        }
        manifest["sample"] = _build_sample(
            scenario, benign, primary_result, primary_record, technique, exploit_rel
        )
        if not benign and confirmed is False and primary_result and primary_result.agent_claimed_success:
            logger.warning(
                "agent claimed success but proof is absent from ground truth — "
                "labeling as unconfirmed (attempt-only sample)"
            )
        if not benign and confirmed is True and scenario.agent.require_exploit_script and not exploit_rel:
            logger.warning(
                "exploit CONFIRMED but no reproduction script was written — "
                "sample lacks an exploit.* artifact"
            )

        manifest["status"] = "success"
        manifest["finished_at"] = datetime.now().astimezone().isoformat()
        _write_json(run_dir / "manifest.json", manifest)
        _write_checksums(run_dir)
        logger.info("Agent dataset saved to %s", run_dir)
        return run_dir

    except KeyboardInterrupt:
        logger.warning("Interrupted — tearing down")
        manifest["status"] = "interrupted"
        _write_json(run_dir / "manifest.json", manifest)
        raise
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = str(exc)
        manifest["finished_at"] = datetime.now().astimezone().isoformat()
        _write_json(run_dir / "manifest.json", manifest)
        _write_checksums(run_dir)
        if isinstance(exc, (RunError, AgentError, EnvironmentError, CaptureError)):
            raise
        raise RunError(str(exc)) from exc
    finally:
        if capture is not None and capture_started:
            capture.abort()
        target.down()


def _plan_techniques(
    scenario: Scenario,
    run_index: int,
    technique_id: str | None,
    recent: list[str],
    benign: bool,
) -> list[Technique]:
    """The ordered techniques to attempt this run."""
    if benign:
        return []
    if technique_id:
        forced = _technique_by_id(scenario, technique_id)
        if forced is None:
            raise RunError(f"unknown technique id '{technique_id}'")
        return [forced]
    return scenario.agent.technique_order(run_index, avoid=recent)


def _technique_by_id(scenario: Scenario, tid: str | None) -> Technique | None:
    if not tid:
        return None
    for technique in scenario.agent.techniques:
        if technique.id == tid:
            return technique
    return None


def _attempt_model(scenario: Scenario, run_index: int, attempt_idx: int) -> str:
    """Model for one attempt: explicit override → variation pool (escalating on
    retry when configured) → the scenario's top-level model."""
    agent = scenario.agent
    if agent.model:
        return agent.model
    if agent.models:
        offset = attempt_idx if agent.retry_escalates_model else 0
        return agent.models[(run_index + offset) % len(agent.models)]
    return scenario.model


def _recent_techniques(
    scenario: Scenario, output_root: Path, limit: int | None = None
) -> list[str]:
    """Technique ids used by recent runs of this scenario (most recent first).

    Feeds anti-repetition. Never returns the whole bank (so at least one fresh
    technique always remains preferable)."""
    bank = [technique.id for technique in scenario.agent.techniques]
    if len(bank) <= 1:
        return []
    if limit is None:
        limit = max(1, len(bank) - 1)
    runs_dir = output_root / scenario.t9_code / "runs"
    if not runs_dir.is_dir():
        return []
    manifests = sorted(
        runs_dir.glob("*/manifest.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    seen: list[str] = []
    for manifest_path in manifests:
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        tid = (data.get("sample") or {}).get("technique_id")
        if tid and tid in bank and tid not in seen:
            seen.append(tid)
        if len(seen) >= limit:
            break
    return seen


def _run_baseline(scenario: Scenario, target: VulhubTarget, run_dir: Path) -> dict[str, Any]:
    """Run the scenario's canonical PoC (no LLM) and check its proof oracle."""
    spec = scenario.agent.baseline
    assert spec is not None
    token = "T9BASE" + secrets.token_hex(6)
    argv = [_expand_baseline(arg, target.host, target.port, token) for arg in spec.command]
    started = datetime.now().timestamp()
    timed_out = False
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=spec.timeout_seconds, check=False
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = _text(exc.stdout) + _text(exc.stderr)
        returncode = 124
        timed_out = True
    except OSError as exc:
        raise RunError(f"baseline PoC could not run: {exc}") from exc

    if spec.proof.type == "container_marker":
        confirmed = _marker_present(target.target_container_id, spec.proof.marker_dir, token)
    elif spec.proof.type == "container_log":
        confirmed = _log_contains(target.target_container_id, spec.proof.log_path, token)
    else:
        confirmed = token in output
    (run_dir / "baseline.txt").write_text(
        f"$ {' '.join(argv)}\nrc={returncode} timed_out={timed_out}\n\n{output[:20000]}\n",
        encoding="utf-8",
    )
    return {
        "confirmed": bool(confirmed),
        "proof_method": spec.proof.type,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(datetime.now().timestamp() - started, 2),
        "log": "baseline.txt",
    }


def _read_container_file(
    container_id: str | None, path: str, max_bytes: int = 20_000
) -> str | None:
    """Harness-side retrieval: read a file out of the TARGET container.

    Keeping this in the orchestrator (which holds the container handle) means the
    agent never needs docker access — it stays a pure network attacker and just
    receives the text as reference material.
    """
    if not container_id:
        return None
    result = subprocess.run(
        ["docker", "exec", container_id, "cat", path],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return None
    text = result.stdout
    if len(text) > max_bytes:
        text = text[:max_bytes] + "\n...[truncated by T9-GPT]"
    return text


def _build_reference_context(
    scenario: Scenario, target: VulhubTarget
) -> tuple[str | None, dict[str, Any] | None]:
    """Resolve the scenario's reference material into injectable text.

    Offline tier: freeform notes + source files read from the target container.
    URLs are surfaced as pointers only (not fetched until the web tier). Returns
    ``(context_text, manifest_record)``; both None when no references are declared.
    """
    ref = scenario.agent.references
    if ref is None or (ref.is_empty() and not ref.allow_web):
        return None, None
    parts: list[str] = []
    record: dict[str, Any] = {
        "notes": bool(ref.notes),
        "source_paths": [],
        "advisory_urls": list(ref.advisory_urls),
        "patch_urls": list(ref.patch_urls),
        "web_enabled": ref.allow_web,
    }
    if ref.notes:
        parts.append("ANALYSIS NOTES:\n" + ref.notes.strip())
    for path in ref.source_paths:
        content = _read_container_file(target.target_container_id, path)
        if content is None:
            record["source_paths"].append({"path": path, "read": False})
            logger.warning("reference source unreadable in target: %s", path)
            continue
        record["source_paths"].append({"path": path, "read": True, "bytes": len(content)})
        parts.append(f"SOURCE FILE {path}:\n{content}")
    if ref.advisory_urls or ref.patch_urls:
        parts.append(
            "REFERENCE URLS (pointers — not fetched in offline mode):\n"
            + "\n".join(ref.advisory_urls + ref.patch_urls)
        )
    context = "\n\n".join(parts) if parts else None
    return context, record


def _check_proof(
    proof: ProofSpec,
    pcap_path: Path,
    token: str,
    container_id: str | None,
    server_port: int | None = None,
) -> bool | None:
    """Dispatch to the ground-truth proof oracle for this technique."""
    if proof.type == "container_marker":
        return _marker_present(container_id, proof.marker_dir, token)
    if proof.type == "container_log":
        return _log_contains(container_id, proof.log_path, token)
    if proof.type == "oob_callback":
        return token_in_pcap_any(pcap_path, token)
    return token_in_http_responses(pcap_path, token, server_port)


def _marker_present(container_id: str | None, marker_dir: str, token: str) -> bool | None:
    """container_marker oracle: did the exploit make the TARGET write the token file?"""
    if not container_id:
        return None
    path = f"{marker_dir.rstrip('/')}/{token}"
    result = subprocess.run(
        ["docker", "exec", container_id, "test", "-f", path],
        capture_output=True, text=True, check=False,
    )
    return result.returncode == 0


def _log_contains(container_id: str | None, log_path: str | None, token: str) -> bool | None:
    """container_log oracle: did the token land in a log file inside the TARGET?"""
    if not container_id or not log_path:
        return None
    result = subprocess.run(
        ["docker", "exec", container_id, "grep", "-F", token, log_path],
        capture_output=True, text=True, check=False,
    )
    return result.returncode == 0


def _agent_block(result: AgentRunResult, exploit_rel: str | None) -> dict[str, Any]:
    return {
        "engine": result.engine,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "stopped_on_proof": result.stopped_on_proof,
        "duration_seconds": round(result.duration_seconds, 2),
        "cost_usd": result.cost_usd,
        "session_id": result.session_id,
        "model": result.model,
        "technique_id": result.technique_id,
        "agent_claimed_success": result.agent_claimed_success,
        "result_label": result.result_label,
        "exploit_script": exploit_rel,
        "transcript": "agent_transcript.txt",
    }


def _build_sample(
    scenario: Scenario,
    benign: bool,
    result: AgentRunResult | None,
    record: dict[str, Any] | None,
    technique: Technique | None,
    exploit_rel: str | None,
) -> dict[str, Any]:
    """Rich, self-describing ground-truth label for the collected sample —
    the actual product T9 hands to detection-model training."""
    label = (result.result_label if result and result.result_label else {}) or {}

    def prefer(field: str, fallback: str | None) -> str | None:
        value = label.get(field)
        return value if value else fallback

    return {
        "kind": "benign" if benign else "attack",
        "cve": None if benign else scenario.cve,
        "technique_id": record.get("technique_id") if record else None,
        "technique_name": technique.name if technique else None,
        "mitre": technique.mitre if technique else None,
        "injection_point": prefer("injection_point", technique.injection_point if technique else None),
        "payload_family": prefer("payload_family", technique.payload_family if technique else None),
        "tool": label.get("tool"),
        "exploit_confirmed": record.get("exploit_confirmed") if record else None,
        "proof_method": record.get("proof_method") if record else None,
        "model": result.model if result else None,
        "cost_usd": result.cost_usd if result else None,
        "duration_seconds": record.get("duration_seconds") if record else None,
        "exploit_script": exploit_rel,
        "agent_notes": label.get("notes"),
    }


def _expand_baseline(value: str, host: str, port: int, token: str) -> str:
    return (
        value.replace("${HOST}", host)
        .replace("${PORT}", str(port))
        .replace("${TOKEN}", token)
    )


def _promote(src: Path, dst: Path) -> bool:
    """Move an attempt artifact up to the run root (no byte duplication)."""
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return True
    return False


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _vulhub_commit() -> str:
    result = subprocess.run(
        ["git", "-C", str(VULHUB_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def put_banner(scenario: Scenario) -> None:
    figlet = Figlet(font="banner4")
    grid = Table.grid(expand=True, padding=1, pad_edge=True)
    grid.add_column(justify="right", ratio=19)
    grid.add_column(justify="left", ratio=31)
    grid.add_row(
        Text.assemble((figlet.renderText("T9"), "bold red")),
        Text(figlet.renderText("Project"), "bold white"),
    )
    print(grid)
    print(f"[bold cyan]T9 Code :[/bold cyan] {scenario.t9_code}")
    print(f"[bold cyan]CVE     :[/bold cyan] {scenario.cve or '—'}")
    print(f"[bold cyan]Name    :[/bold cyan] {scenario.name}")
    print(f"[bold cyan]Engine  :[/bold cyan] claude-loop (budget ${scenario.agent.budget_usd:.2f})")
    print(f"[bold cyan]Capture :[/bold cyan] {scenario.capture.mode}")
    print()


def _list_scenarios(scenarios: list[Scenario]) -> None:
    table = Table(title="T9 scenarios", show_lines=True)
    table.add_column("T9 Code", style="cyan")
    table.add_column("CVE", style="yellow")
    table.add_column("Name")
    table.add_column("Lane")
    table.add_column("Techniques")
    table.add_column("Agent-runnable")
    for scenario, errors in validate_catalog(scenarios):
        table.add_row(
            scenario.t9_code,
            scenario.cve or "—",
            scenario.name,
            scenario.lane,
            str(len(scenario.agent.techniques)),
            "[green]yes[/green]" if not errors else "[red]" + "; ".join(errors) + "[/red]",
        )
    print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="T9-GPT controlled attack-traffic dataset generator"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("list", "validate", "agent"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", required=True, metavar="FILE")
        if command == "agent":
            child.add_argument("--t9-code", metavar="CODE")
            child.add_argument("--output-root", type=Path, default=BASE_DIR)
            child.add_argument("--model")
            child.add_argument("--budget", type=float, metavar="USD",
                               help="override the per-run dollar cap")
            child.add_argument("--attempts", type=int, metavar="N",
                               help="override technique-cycling retry cap (max_attempts)")
            child.add_argument("--technique", metavar="ID",
                               help="force a specific technique id from the bank")
            child.add_argument("--benign", action="store_true",
                               help="collect a benign hard-negative sample instead of an attack")
            child.add_argument("--allow-web", action="store_true",
                               help="enable WebFetch/WebSearch CVE research (agentic-RAG web tier)")
            child.add_argument("--repeat", type=int, default=1, metavar="N",
                               help="run the scenario N times for log diversity")
    return parser


def _normalize_legacy_args(argv: list[str]) -> list[str]:
    if argv and argv[0] in {"list", "validate", "agent"}:
        return argv
    if "--list" in argv:
        return ["list", *[value for value in argv if value != "--list"]]
    return ["agent", *argv]


def main(argv: list[str] | None = None) -> None:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(_normalize_legacy_args(raw_args))
    try:
        scenarios = load_scenarios(args.config)
        if args.command == "list":
            _list_scenarios(scenarios)
            return
        if args.command == "validate":
            _list_scenarios(scenarios)
            failures = sum(bool(errors) for _, errors in validate_catalog(scenarios))
            if failures:
                raise SystemExit(2)
            return

        if args.command == "agent":
            scenario = select_scenario(scenarios, args.t9_code)
            if args.model:
                scenario.agent.model = args.model
            if args.budget:
                scenario.agent.budget_usd = args.budget
            if args.attempts:
                scenario.agent.max_attempts = args.attempts
            if args.allow_web:
                if scenario.agent.references is None:
                    scenario.agent.references = ReferenceConfig(allow_web=True)
                else:
                    scenario.agent.references.allow_web = True
            put_banner(scenario)
            repeat = max(1, args.repeat)
            for index in range(1, repeat + 1):
                if repeat > 1:
                    logger.info("Diversity run %d/%d", index, repeat)
                hint = (
                    f"This is collection run {index} of {repeat}."
                    if repeat > 1 else None
                )
                output = run_agent_scenario(
                    scenario,
                    args.output_root,
                    diversity_hint=hint,
                    run_index=index - 1,
                    benign=args.benign,
                    technique_id=args.technique,
                )
                label = "Benign dataset" if args.benign else "Agent dataset"
                print(f"[bold green]{label}:[/bold green] {output}")
            return
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        logger.error("catalog error: %s", exc)
        raise SystemExit(2) from exc
    except EnvironmentError as exc:
        logger.error("environment failed: %s", exc)
        raise SystemExit(4) from exc
    except CaptureError as exc:
        logger.error("capture failed: %s", exc)
        raise SystemExit(5) from exc
    except AgentError as exc:
        logger.error("agent failed: %s", exc)
        raise SystemExit(7) from exc
    except RunError as exc:
        logger.error("run failed: %s", exc)
        raise SystemExit(6) from exc


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _write_checksums(run_dir: Path) -> None:
    checksum_path = run_dir / "SHA256SUMS"
    lines: list[str] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path == checksum_path:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(run_dir)}")
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
