# T9GPT — recovered source

Recovered 2026-08-20 from the frozen WSL2 ext4 image
`D:\ubuntu-damaged-backup.vhdx` (snapshot 2026-08-19 16:27), after
`/home/csrc` was unlinked on 2026-08-19 (~484,000 files deleted).

## How these files were obtained

Claude Code transcripts (`~/.claude/projects/**/*.jsonl`) were carved out of
free ext4 blocks. Each transcript line is an independently parseable JSON
object, so fragmentation did not matter. Write/Edit tool calls and Read
results in those lines carry verbatim file bodies; the newest non-empty
version of each path was written back to its original location.

20,916 transcript records across 163 sessions were recovered.

## Fidelity

VERBATIM — byte-exact as Claude Code last saw them. 15 of 18 Python files
parse cleanly under Python 3.12.

## Known gaps

These three are TRUNCATED — recovered from a partial Read or from an Edit
fragment, not a full-file snapshot. Copies are kept in `_PARTIAL/`.

  - planner.py                        unterminated docstring at line 129
  - tests/test_agent_orchestration.py starts mid-file
  - tests/test_agent_runner.py        starts mid-file

Mentioned in transcripts but not recovered:

  - _demo/leaked_exploit_example.sh
  - _demo2/.../work/exploit.sh
  - create_pipeline_ppt_compat.py

`tool.py` and `manifest.json` are named in README.md/CLAUDE.md but appear
nowhere in any transcript, so they may never have existed.

## Not yet applied

A free-block content carve of the whole 1 TB image is still running and may
recover the truncated files verbatim. Do not discard the .vhdx images until
that has been checked.
