# T9-GPT

T9-GPT generates labeled attack-traffic datasets for training network
intrusion-detection (IDS/NDR/EDR) models. A bounded, budget-capped Claude
agent (`claude-loop`) exploits a known CVE against a disposable Vulhub Docker
target; T9-GPT captures the traffic, checks success against ground truth (not
the agent's self-report), and writes a labeled sample.

It is not a general-purpose penetration-testing agent. It only attacks
scenarios you define — a known CVE, an isolated disposable target, and a
capped budget — and it never scans, enumerates, or touches anything outside
the one target host:port it is given.

## Requirements

- Python 3.12 and `uv`
- Docker Compose access for the current user
- A local Vulhub checkout at `~/vulhub` or `$VULHUB_ROOT`
- Claude CLI authenticated with your subscription (no `ANTHROPIC_API_KEY` is
  used — the agent runs on your Claude subscription, not billed API calls)
- Optional `tshark`/`capinfos` for inspecting captures

Install dependencies:

```bash
cd t9gpt
uv sync
```

## Commands

```bash
# Show the scenario catalog and whether each one is runnable
uv run python orchestrator.py list --config scenarios/example.json

# Validate the whole catalog (non-zero exit if anything is unrunnable)
uv run python orchestrator.py validate --config scenarios/example.json

# Collect one attack sample
uv run python orchestrator.py agent \
  --config scenarios/example.json \
  --t9-code T9-25-02-S-N-CD

# Collect a benign (non-attack) hard-negative sample from the same target
uv run python orchestrator.py agent \
  --config scenarios/example.json \
  --t9-code T9-25-02-S-N-CD --benign

# Collect N diverse samples in one call (technique/model rotate automatically)
uv run python orchestrator.py agent \
  --config scenarios/example.json \
  --t9-code T9-25-02-S-N-CD --repeat 10
```

Other `agent` flags: `--technique ID` forces one technique from the bank,
`--model` / `--budget` override the scenario's model and dollar cap, `--attempts`
overrides the technique-cycling retry cap, and `--allow-web` turns on
`WebFetch`/`WebSearch` for CVE research (agentic-RAG web tier — use only on
scenarios pointing at *known*, published CVEs; see "Safety boundary" below).

## How one run works

1. **Target up** — `VulhubTarget` runs `docker compose up` for the scenario's
   Vulhub path and waits for the readiness probe.
2. **Reference injection (optional)** — if the scenario declares
   `agent.references`, the harness resolves `notes` (freeform analysis text)
   and `source_paths` (files read out of the *target* container via
   `docker exec`) into context text injected into the agent's task. This lets
   the agent develop an exploit from primary sources instead of only
   recalling a known PoC. With `--allow-web`, `WebFetch`/`WebSearch` are also
   granted so the agent can read the CVE's public advisory/patch diff.
3. **Baseline preflight (optional)** — if the scenario declares
   `agent.baseline`, a no-LLM canonical PoC runs first. If it doesn't confirm
   the target is exploitable, the run stops here — no tokens spent.
4. **Attempt loop** — for up to `agent.max_attempts` attempts: pick a
   technique (rotated for diversity, recently-used ones pushed to the back),
   start a packet capture, run the bounded `claude -p` agent
   (`--max-budget-usd`, `--permission-mode bypassPermissions`,
   `--allowed-tools Bash` (+`WebFetch WebSearch` if web is enabled)), stop the
   capture, then check the **ground-truth proof oracle** (see below) — never
   the agent's transcript. An unconfirmed attempt retries with the next
   technique; a confirmed one stops the loop.
5. **Teardown** — the target container, network, and volumes are always torn
   down, even on failure or `Ctrl-C`.

## Proof oracles (ground truth, not self-report)

An agent's own claim of success is not trusted — `curl -v` echoes the request
back, so a token can appear in the transcript even on a failed exploit. Every
scenario declares a `proof` type, checked independently after the fact:

- `reflected_http` — the proof token appears in an HTTP *response* in the
  capture (reflected RCE).
- `container_marker` — the exploit made the target write a token-named file
  (`docker exec test -f`); the oracle for blind RCE that reflects nothing.
- `oob_callback` — the token appears anywhere in the capture (e.g. an
  outbound callback); weakest oracle, use only for inherently out-of-band
  exploit classes.
- `container_log` — the token was written into a log file inside the target
  (e.g. Log4Shell: a failed JNDI lookup logs the payload).

A technique can override the scenario's default oracle (e.g. one technique in
a bank is a "blind marker" variant of another).

## Scenario file shape

Each scenario needs an `environment` (Vulhub path, service, port, readiness
probe) and an `agent` block. The `agent` block's `techniques` list is what
makes collected logs diverse — the agent carries out exactly *one* technique
per run, and each technique is also the ground-truth label attached to the
resulting sample (MITRE ATT&CK id, injection point, payload family). See
`scenarios/example.json` for full examples, including a Log4Shell scenario
that uses `references.notes` to prime the agent on a CVE it may not recall
from memory, and a benign-hard-negative profile per scenario.

## Outputs

Each run is stored under:

```text
<T9 code>/runs/<run id>/
```

Key artifacts:

- `capture.pcap` — the packet capture of the confirmed (or final) attempt
- `agent_transcript.txt` — the agent's full stream-json transcript
- `exploit.<sh|py>` — the standalone reproduction script the agent wrote
- `manifest.json` — run metadata: engine, techniques planned/used, per-attempt
  records, the ground-truth `exploit_confirmed` label, and the `sample` block
  (the actual product handed to detection-model training)
- `attempts/aNN/` — per-attempt capture, transcript, and work directory for
  every attempt in the run (not just the winning one)
- `baseline.txt` — output of the no-LLM baseline PoC, if the scenario has one
- `SHA256SUMS` — checksums of every artifact in the run directory

## Safety boundary

- Every scenario targets a **known, published CVE** against a **disposable,
  isolated Vulhub container** — nothing is production or third-party.
- The `claude-loop` system prompt is a hard leash: the agent is told the
  vulnerability is already confirmed (so it skips recon), and is forbidden
  from scanning, enumerating, pivoting, or touching anything outside the one
  target host:port it is given.
- `--max-budget-usd` is a real dollar cap enforced by the Claude CLI itself,
  plus a wall-clock timeout backstop per run.
- `--allow-web` grants `WebFetch`/`WebSearch` for reading a *known* CVE's
  public advisory/patch — it must never be pointed at a scenario built around
  an undisclosed or unknown vulnerability, since that would mean asking the
  agent to autonomously discover a novel exploit rather than reproduce a
  known one.
- The agent's own claim of success is never trusted as the dataset label —
  every sample's `exploit_confirmed` field comes from an independent
  ground-truth proof oracle (see above).
