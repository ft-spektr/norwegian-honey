"""Load JSON from pure files or Makefile/curl captures with leading noise."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Lines captured when redirecting `make target > file` or `make -n target > file`.
_NOISE_LINE = re.compile(
    r"^(?:"
    r"make\[\d+\]:.*"
    r"|curl\b.*"
    r"|\|.*"
    r")$",
)

# JSON root must start a line (after optional indent) — avoids parsing make[1] as [1].
_JSON_START = re.compile(r"^(\s*)([\[{])", re.MULTILINE)


def _strip_noise_lines(raw: str) -> str:
    kept: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _NOISE_LINE.match(stripped):
            continue
        # Makefile recipe fragments echoed into captures (e.g. curl flags, PRETTY pipe).
        if stripped.startswith(("-H", "-F", "-d", "-X", "-s")) and not stripped.startswith(("{", "[")):
            continue
        if stripped.endswith("\\"):
            continue
        kept.append(line)
    return "\n".join(kept)


def parse_json_document(raw: str) -> Any:
    """Parse JSON from text that may include curl/Makefile lines before the payload."""
    cleaned = _strip_noise_lines(raw).strip()
    if not cleaned:
        raise json.JSONDecodeError("Empty input", raw, 0)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for match in _JSON_START.finditer(cleaned):
        index = match.start(2)
        try:
            document, _ = decoder.raw_decode(cleaned, index)
            return document
        except json.JSONDecodeError:
            continue

    raise json.JSONDecodeError("No JSON document found in input", raw, 0)


def load_json_document(path: Path | str) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    return parse_json_document(text)
