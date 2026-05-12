"""C5 threshold loader — reads ``evals/thresholds.yaml`` if present, else uses
hardcoded defaults that mirror the file's placeholder values.

We parse the YAML by hand (a simple flat key: value format) so we avoid adding
pyyaml as a hard dependency; the transitive availability of pyyaml is not
guaranteed across all install configurations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Path is resolved relative to this file's location so the loader works from
# any working directory (tests, scripts, the CLI).
_THRESHOLDS_PATH = Path(__file__).parent.parent.parent.parent / "evals" / "thresholds.yaml"


@dataclass(frozen=True, slots=True)
class Thresholds:
    """The five C5 thresholds.  All are inclusive upper bounds (≥ threshold → FAIL)."""

    max_total_tokens: int
    max_cost_usd: float
    max_wall_time_s: float
    max_supervisor_hops: int
    amplification_k: float


# Hardcoded defaults that mirror evals/thresholds.yaml.
_DEFAULTS = Thresholds(
    max_total_tokens=20_000,
    max_cost_usd=0.25,
    max_wall_time_s=90.0,
    max_supervisor_hops=4,
    amplification_k=50.0,
)

# A minimal flat-YAML parser: lines of the form "key: value", ignoring comments
# and blank lines.  Sufficient for evals/thresholds.yaml; not a general parser.
_KV_RE = re.compile(r"^\s*([a-z_]+)\s*:\s*([0-9.]+)", re.MULTILINE)


def _parse_flat_yaml(text: str) -> dict[str, float]:
    """Return every ``key: numeric_value`` pair found in *text*."""
    return {m.group(1): float(m.group(2)) for m in _KV_RE.finditer(text)}


def load_thresholds(path: Path | None = None) -> Thresholds:
    """Load thresholds from *path* (default: ``evals/thresholds.yaml``).

    Falls back to :data:`_DEFAULTS` if the file does not exist or cannot be
    parsed, so callers always get a valid :class:`Thresholds` object.
    """
    resolved = path or _THRESHOLDS_PATH
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError:
        return _DEFAULTS

    kv = _parse_flat_yaml(text)
    if not kv:
        return _DEFAULTS

    return Thresholds(
        max_total_tokens=int(kv.get("max_total_tokens", _DEFAULTS.max_total_tokens)),
        max_cost_usd=kv.get("max_cost_usd", _DEFAULTS.max_cost_usd),
        max_wall_time_s=kv.get("max_wall_time_s", _DEFAULTS.max_wall_time_s),
        max_supervisor_hops=int(kv.get("max_supervisor_hops", _DEFAULTS.max_supervisor_hops)),
        amplification_k=kv.get("amplification_k", _DEFAULTS.amplification_k),
    )
