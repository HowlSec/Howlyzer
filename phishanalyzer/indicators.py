"""Loads the editable indicators.json knowledge base."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

_DEFAULT_PATH = Path(__file__).parent / "indicators.json"


@lru_cache(maxsize=4)
def load_indicators(path: str | None = None) -> dict:
    """Load the indicators knowledge base.

    Resolution order: explicit ``path`` arg, then ``PHISHANALYZER_INDICATORS``
    env var, then the bundled default next to this module.
    """
    candidate = path or os.environ.get("PHISHANALYZER_INDICATORS") or str(_DEFAULT_PATH)
    with open(candidate, encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_comment", None)
    return data
