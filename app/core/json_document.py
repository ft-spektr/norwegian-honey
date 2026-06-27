"""Load JSON from pure files or Makefile/curl captures with leading noise."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_json_document(raw: str) -> Any:
    """Parse JSON from text that may include curl/Makefile lines before the payload."""
    stripped = raw.strip()
    if not stripped:
        raise json.JSONDecodeError("Empty input", raw, 0)

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(raw):
        if char not in "{[":
            continue
        try:
            document, _ = decoder.raw_decode(raw, index)
            return document
        except json.JSONDecodeError:
            continue

    raise json.JSONDecodeError("No JSON document found in input", raw, 0)


def load_json_document(path: Path | str) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    return parse_json_document(text)
