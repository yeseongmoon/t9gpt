---
name: t9-collect
description: >-
  Operate the T9-GPT attack-traffic dataset lab — collect a labeled NDR/EDR
  sample by running a bounded Claude agent against a disposable Vulhub CVE
  target, or author/validate a new CVE scenario. Use when the user wants to
  "collect a T9 sample", "run a scenario", "generate attack traffic / a pcap for
  a CVE", "add a CVE to the catalog", "make a benign hard-negative", "collect N
  diverse samples", or check/verify a run's ground-truth label. Research lab only:
  known published CVEs, isolated disposable containers, never real targets.
---

# T9-GPT collection & scenario authoring

This skill drives the T9-GPT harness in `2026/t9gpt/`. Read `CLAUDE.md` in that
directory first — the **Non-negotiable rules** there bind every action here.
All commands run from `2026/t9gpt/`.

## Guardrails (refuse or stop if any is violated)

- Target must be a **known, published CVE** on a **disposable Vulhub container**
  the harness starts and tears down. Never a real/production/third-party host.
- Never weaken the agent leash (no recon/scanners, single target host:port, no
  persistence/pivot/exfil/DoS). Never relabel a sample from the transcript —
  only the ground-truth proof oracle sets `exploit_confirmed`.
- `--allow-web` is permitted **only** for scenarios pointing at a published CVE.
- Keep budgets small (`budget_usd` default 0.5). Confirm before running a batch
  (`--repeat`) or any single run above ~$2 of cumulative budget.

## Step 0 — Preflight (always)

```bash
cd 2026/t9gpt
uv run python orchestrator.py list --config scenarios/example.json
```

Check: the target scenario shows **Agent-runnable: yes**; `docker info` works;
`claude`, `tshark`, `capinfos`, `uv` are on PATH; Vulhub exists at `~/vulhub`
(or `$VULHUB_ROOT`). If a scenario is not runnable, fix the scenario (Path B)
before spending tokens.

## Path A — Collect from an existing scenario

1. **Validate** the catalog: `uv run python orchestrator.py validate --config <catalog>`.
2. **Attack sample** (start cheap; add `--budget` only if it's genuinely needed):
   ```bash
   uv run python orchestrator.py agent --config <catalog> --t9-code <CODE> \
     --output-root <dataset-dir>
   ```
   Optional: `--technique <ID>` to force one variant, `--attempts N` to let it
   cycle techniques within one target lifecycle, `--allow-web` for CVE research.
3. **Benign twin** (hard negative from the identical target/harness):
   ```bash
   uv run python orchestrator.py agent --config <catalog> --t9-code <CODE> --benign \
     --output-root <dataset-dir>
   ```
4. **Diversity batch** once a single run is confirmed working:
   `--repeat N` (technique + model rotate automatically; recently-used techniques
   are pushed back for anti-repetition).
5. **Verify ground truth** (Step V) — do not report success from console text.

Prefer an explicit `--output-root` (e.g. a `datasets/` or `_scratch/` dir) so
runs don't scatter into the default `2026/` parent. Prefix throwaway roots with `_`.

## Path B — Author a new CVE scenario

1. **Confirm the Vulhub env exists**: the compose dir is
   `~/vulhub/<environment.path>`. The Vulhub advisory id often differs from the
   CVE id (e.g. CVE-2023-50164 → `struts2/s2-066`) — verify the actual folder.
2. **Add a `Scenario`** to a catalog JSON (mirror an entry in
   `scenarios/example.json`). Required/important fields:
   - `t9_code` matching `^T9-\d{2}-\d{2}-[SM]-(?:N|E|NE)-[A-N]+$`; trailing
     letters are MITRE tactics (A=Reconnaissance … N=Impact), and `N/E/NE`
     mirrors the network/endpoint/multi `lane`.
   - `cve`, `software`, `environment` (`path`, `service`, `target_port`,
     `readiness` probe), `capture.ports`.
   - `agent.techniques[]` — a **bank** of distinct exploitation variants; each is
     one run's job *and* its ground-truth label (`mitre`, `injection_point`,
     `payload_family`, `tool`). More techniques ⇒ more log diversity.
   - `agent.proof` (or per-technique `proof`) — pick the oracle:
     `reflected_http` (token echoed in an HTTP response), `container_marker`
     (blind RCE writes a token-named file under `marker_dir`), `container_log`
     (token written to a target-side `log_path`, e.g. Log4Shell), `oob_callback`
     (token anywhere in the pcap — weakest, out-of-band classes only).
   - `agent.benign_profile` — a one-line description of legit traffic for `--benign`.
   - `agent.baseline` (strongly preferred) — a no-LLM canonical PoC (`${HOST}`,
     `${PORT}`, `${TOKEN}` expanded) so a broken target fails **token-free**
     before the agent runs.
3. `validate` the catalog, then do **one cheap run** and confirm the manifest's
   `exploit_confirmed` is `true` from the oracle before trusting the scenario or
   batching it.

## Step V — Verify a run (ground truth, not the console)

```bash
run=$(ls -td <dataset-dir>/<CODE>/runs/*/ | head -1)
python -c "import json,sys; m=json.load(open('$run/manifest.json')); \
print('status        ', m.get('status')); \
print('confirmed(GT) ', m.get('exploit_confirmed')); \
print('claimed(agent)', (m.get('agent') or {}).get('agent_claimed_success')); \
print('cost_usd      ', (m.get('agent') or {}).get('cost_usd')); \
print('technique     ', (m.get('sample') or {}).get('technique_id')); \
print('proof_method  ', (m.get('sample') or {}).get('proof_method'))"
tshark -r "$run/capture.pcap" | head        # eyeball the captured traffic
```

- The authoritative label is **`exploit_confirmed`** (the oracle). If it is
  `false`/`null` but the agent *claimed* success, the sample is unconfirmed —
  report it as such; do not upgrade it.
- `exploit_confirmed: true` but no `exploit.*` script ⇒ the reproducible artifact
  is missing; note it.
- `status: target_unexploitable` ⇒ the baseline failed and no tokens were spent;
  the Vulhub target/build is the problem, not the agent.

## After changes to the harness

If you edited any `.py`, run the quality gates and keep them green:

```bash
uv run pytest        # token-free, Docker-free
uv run ruff check .
uv run mypy .
```

## Report back

Summarize: T9 code + CVE, attack vs benign, **ground-truth `exploit_confirmed`**
(with the oracle used), cost, whether a reproduction script was written, and the
run directory path. Flag any agent-claimed-but-unconfirmed result explicitly.
