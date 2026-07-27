"""Canonical-JSON hashing for argument-bound grants.

The ONLY implementation of the args-hash rule, used server-side at issue time and
redeem time. No client, in either repo, ever computes or transmits a hash — the
server is the sole hasher, which is what keeps a cross-repo canonicalizer from ever
drifting out of sync with this one.

Rule (pinned; documented in docs/SERVICE.md):
  sort_keys=True (recursive, code-point order), separators=(",", ":"),
  ensure_ascii=True, allow_nan=False; arrays keep caller order; no Unicode
  normalization (NFC vs NFD hash differently, by design); int and float never
  conflate (1 != 1.0); SHA-256 over the UTF-8 encoding.

This module is deliberately independent of ``store._canonical`` — that helper is
used for audit-body serialization and is left untouched so this feature cannot
change the hash of a single existing audit record.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping


class ArgsNotHashable(ValueError):
    """Args contain something the canonical form cannot represent. Always a 400."""


def _check(obj: Any, path: str) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ArgsNotHashable(f"{path}: non-string object key {k!r}")
            _check(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check(v, f"{path}[{i}]")
    elif isinstance(obj, bool) or obj is None or isinstance(obj, (str, int)):
        # bool is checked before int (bool is an int subclass) purely for clarity;
        # both are accepted as-is either way.
        pass
    elif isinstance(obj, float):
        if not math.isfinite(obj):
            raise ArgsNotHashable(f"{path}: non-finite float (NaN/Infinity)")
    else:
        raise ArgsNotHashable(f"{path}: unsupported type {type(obj).__name__}")


def canonical_args(args: Mapping[str, Any]) -> str:
    """Render ``args`` as the pinned canonical JSON string, or raise ``ArgsNotHashable``."""
    if not isinstance(args, Mapping):
        raise ArgsNotHashable("args must be a JSON object")
    plain = dict(args)
    _check(plain, "args")
    return json.dumps(plain, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False)


def args_hash(args: Mapping[str, Any]) -> str:
    """SHA-256 hex digest of the canonical rendering of ``args``."""
    return hashlib.sha256(canonical_args(args).encode("utf-8")).hexdigest()
