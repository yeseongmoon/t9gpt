# T9-GPT — agent guide

T9-GPT generates **labeled attack-traffic datasets** for training network
intrusion-detection (IDS/NDR/EDR) models. A bounded, budget-capped Claude agent
(`claude-loop`) exploits **one known CVE** against a **disposable Vulhub Docker
target**; the harness captures the traffic, checks success against **ground
truth** (not the agent's self-report), and writes a labeled sample plus a
reproducible exploit script.

This is a **research-only purple-teaming lab**. It exists to *produce data from
vulnerable environments we stand up ourselves*, never to attack anything real.
Read the "Non-negotiable rules" section before changing anything that touches
the agent leash, target scope, or proof labeling. `README.md` has the full
run-lifecycle narrative; this file is the operating manual for working *on* the
code.

## What this is / is NOT

- IS: automated, isolated, reproducible exploitation of **published** CVEs
  against throwaway containers, for the sole purpose of collecting NDR/EDR logs
  with trustworthy ground-truth labels.
- IS NOT: a penetration-testing agent, a scanner, an exploit-discovery tool, or
  anything that runs against a host we do not own and dispose of. There is no
  recon, enumeration, pivoting, persistence, or exfiltration anywhere in scope.

## Non-negotiable rules (do not weaken these)

1. **Known, published CVEs against disposable Vulhub targets only.** Never point
   a scenario at production, third-party, or anything not spun up and torn down
   by the harness. The target is one `host:port` that lives and dies inside one
   run.
2. **The agent leash is load-bearing.** `CLAUDE_LOOP_SYSTEM_PROMPT` and
   `BENIGN_SYSTEM_PROMPT` in `agent_runner.py` are a hard leash: vuln is
   pre-confirmed (no fingerprinting), **no scanners/enumerators** (nmap,
   gobuster, ffuf, nikto, sqlmap, hydra…), touch only the given target, no
   persistence/pivot/escalation/exfil/DoS, one technique per run, stop on proof.
   `--permission-mode bypassPermissions` is only safe *because* of this leash +
   container isolation. If you edit these prompts, preserve every constraint.
3. **Ground truth, never self-report.** A sample's `exploit_confirmed` label
   comes from an independent **proof oracle** (`_check_proof` in
   `orchestrator.py` → `collector.token_in_http_responses` / `token_in_pcap_any`
   / container marker / container log). `agent_claimed_success` (proof token seen
   in the transcript) is *advisory only* — `curl -v` echoes the request, so the
   token can appear even on a failure. Never relabel a sample from the transcript.
4. **Always tear down.** `VulhubTarget.down()` runs in `finally`, is idempotent,
   and removes containers + networks + volumes. Any new lifecycle path must keep
   that guarantee — a run must leave zero residue even on crash/`Ctrl-C`.
5. **`--allow-web` is for KNOWN CVEs only.** It grants WebFetch/WebSearch so the
   agent can read a *published* advisory/patch. Never enable it on a scenario
   built around an undisclosed or unknown vulnerability — that would be asking
   the agent to discover a novel exploit, which is out of scope.
6. **Runs on the Claude subscription, not an API key.** `agent_runner.py`
   deliberately pops `ANTHROPIC_API_KEY` from the child env. Do not reintroduce
   API-key billing paths.
7. **Minimize tokens.** `agent.budget_usd` (→ `claude --max-budget-usd`) is a
   hard per-run cap and the primary cost lever; keep defaults small (0.5).
   Stop-on-proof and the optional no-LLM `baseline` preflight both exist to avoid
   paying to fail — do not regress them.

## Architecture (module map)

All code is single-directory, flat imports (`pythonpath = ["."]`).

- `models.py` — **pydantic v2 schema is the source of truth.** `Scenario`,
  `AgentConfig`, `Technique`, `ProofSpec`, `EnvironmentConfig`, `CaptureConfig`,
  etc. Validation, the `T9-…` code regex, MITRE tactic-letter map, and the v1→v2
  flat-JSON migration all live here. Add new config as validated fields here first.
- `environment.py` — `VulhubTarget`: `docker compose up/down`, readiness probe,
  container id/ip + published-port resolution. `preflight()` reports missing
  docker/git or a dead daemon.
- `collector.py` — `PacketCapture` (tcpdump sidecar sharing the target's netns,
  dropped-packet accounting) + the pcap proof oracles.
- `agent_runner.py` — the bounded `claude -p` engine: system prompts (the leash),
  per-run task builder, stream-json parsing, **stop-on-proof** termination,
  process-group kill. Tokens are spent **only here**.
- `orchestrator.py` — the CLI + run loop: plan techniques → `up` →
  [reference injection] → [baseline preflight] → capture+agent ×`max_attempts`
  → ground-truth check → assemble `manifest.json`/`sample` → teardown →
  `SHA256SUMS`.
- `scenarios/*.json` — the scenario catalog (the CVEs you can collect). This is
  where new lab targets are added.
- `tests/` — token-free, Docker-free smoke tests (monkeypatch the docker
  lifecycle and the paid agent).

## Common commands (run from `2026/t9gpt/`)

```bash
uv sync                                             # install deps

uv run python orchestrator.py list     --config scenarios/example.json
uv run python orchestrator.py validate --config scenarios/example.json   # nonzero exit if any scenario is unrunnable

# Collect one attack sample
uv run python orchestrator.py agent --config scenarios/example.json --t9-code T9-25-02-S-N-CD
# Benign hard-negative from the same target
uv run python orchestrator.py agent --config scenarios/example.json --t9-code T9-25-02-S-N-CD --benign
# N diverse samples (technique/model rotate automatically)
uv run python orchestrator.py agent --config scenarios/example.json --t9-code T9-25-02-S-N-CD --repeat 10
```

Useful `agent` flags: `--budget USD`, `--technique ID`, `--attempts N`,
`--model NAME`, `--allow-web`, `--output-root DIR`.

Quality gates before finishing a change:

```bash
uv run pytest            # must stay token-free & Docker-free
uv run ruff check .
uv run mypy .            # pyright is also configured
```

## Outputs

A run writes `<output-root>/<T9-code>/runs/<run-id>/` with `capture.pcap`,
`agent_transcript.txt`, `exploit.<sh|py>`, `manifest.json` (engine, techniques,
per-attempt records, the ground-truth `exploit_confirmed` label, and the
`sample` block handed to training), `attempts/aNN/`, optional `baseline.txt`,
and `SHA256SUMS`. **Default `--output-root` is the `2026/` dir** (parent of
`t9gpt`); pass an explicit `--output-root` for real collection so datasets don't
scatter. Prefix throwaway experiment roots with `_` (as `_demo/`, `_abtest/`,
`_rag_probe/` already do). Run artifacts are data, not source — keep them out of
any future git history.

## Adding a scenario (the core expansion loop)

1. Confirm the CVE exists in the local Vulhub checkout (`~/vulhub` or
   `$VULHUB_ROOT`) — `environment.path` is relative to that root, and the Vulhub
   *advisory id* (e.g. `struts2/s2-066`) often differs from the CVE id.
2. Add a `Scenario` object to a catalog JSON: `t9_code` (must match
   `^T9-\d{2}-\d{2}-[SM]-(?:N|E|NE)-[A-N]+$`), `cve`, `environment`, `capture`
   ports, and an `agent` block with a **technique bank** (each technique is one
   distinct exploitation variant *and* the ground-truth label), a `proof` oracle,
   a `benign_profile`, and — strongly preferred — a no-LLM `baseline` PoC so a
   broken target fails token-free.
3. Pick the right proof oracle: `reflected_http` (RCE echoes token in a
   response), `container_marker` (blind RCE writes a token-named file),
   `container_log` (token lands in a target-side log, e.g. Log4Shell),
   `oob_callback` (token appears anywhere in the capture — weakest, OOB only).
4. `validate`, then a single cheap run, then check the run's `manifest.json`
   `exploit_confirmed` is `true` from the oracle before trusting the scenario.

Trailing tactic letters are MITRE ATT&CK tactics per the `TACTIC_LETTER_NAMES`
map in `models.py` (A=Reconnaissance … N=Impact); `N/E/NE` mirrors the
network/endpoint/multi lane.

## Tools available on this host

`docker`, `claude` (CLI, subscription-auth), `uv`, `tshark` + `capinfos` (pcap
inspection — the oracles degrade to `None`/uncheckable without tshark), and a
Vulhub checkout at `~/vulhub`. Inspect a capture with
`tshark -r capture.pcap` / `capinfos capture.pcap`.

## Conventions

- Python 3.12, `from __future__ import annotations`, fully typed, pydantic v2 for
  all external data. Small pure helpers; `logging`/`rich` for output. Match the
  surrounding style.
- Keep `tests/` runnable with no daemon and no tokens — that is what catches
  import/orchestration regressions before a paid run.
- The engine is **`claude-loop` only**. (The separate `2026/PentestGPT/` checkout
  is reference/prior-art, not wired into this harness.)
