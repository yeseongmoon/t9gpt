#!/usr/bin/env python3

import json
import logging
from pathlib import Path

import anthropic

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a cybersecurity analyst specializing in MITRE ATT&CK framework mapping.
Given a penetration testing session log, extract every distinct attack action and
map each one to the most specific MITRE ATT&CK technique (and sub-technique where
applicable). Return ONLY a JSON array — no prose, no markdown fences.
"""

_USER_TEMPLATE = """\
Map the following pentest session to MITRE ATT&CK techniques.

Return a JSON array of objects with this schema:
[
  {{
    "tactic": "<tactic name>",
    "technique_id": "<Txxxx.xxx>",
    "technique_name": "<name>",
    "evidence": "<one sentence from the log that justifies this mapping>"
  }}
]

Session log:
{context}
"""


class MitreMapper:
    def __init__(self, model: str = "claude-sonnet-4-6") -> None:
        self.client = anthropic.Anthropic()
        self.model = model

    def map_from_context(self, context_file: Path) -> list[dict]:
        context = context_file.read_text(encoding="utf-8")
        logger.info("Sending context to %s for MITRE mapping...", self.model)

        message = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": _USER_TEMPLATE.format(context=context)}
            ],
        )

        raw = message.content[0].text.strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("MITRE mapper returned non-JSON — saving raw text")
            return [{"raw": raw}]

    def save(self, mapping: list[dict], output_path: Path) -> None:
        output_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")
        logger.info("MITRE map saved → %s", output_path)
