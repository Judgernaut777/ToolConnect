"""Performance regression tripwires — not benchmarks.

Each ceiling is ~100x the measured baseline on the development box, so these fire on
an algorithmic regression (an accidental O(n^2), a per-call re-parse) rather than on
normal timing jitter. They are deterministic in structure: best-of-N minimum, which
is robust to a noisy shared machine. Marked `perf` so they can be deselected with
`-m "not perf"` in a constrained CI environment.

Baselines measured 2026-07-11: build 0.32ms, lookup 0.001ms, analyze(53) 0.03ms,
drift 0.01ms. Ceilings below leave two orders of magnitude of headroom.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "fixtures")]

from real_catalog import CODING_AGENT_TOOLSET, build_catalog  # noqa: E402

from toolconnect.flow import analyze_toolset  # noqa: E402
from toolconnect.policy import CedarPolicyEngine, Principal  # noqa: E402

from conftest import BASIC_CEDAR  # noqa: E402

pytestmark = pytest.mark.perf


def _best_ms(fn, n: int = 5) -> float:
    times = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return min(times) * 1e3


def test_registry_startup_under_50ms():
    assert _best_ms(build_catalog) < 50.0


def test_tool_lookup_under_5ms():
    c = build_catalog()
    assert _best_ms(lambda: c.invocable("filesystem", "read_file")) < 5.0


def test_toolset_resolution_under_5ms():
    c = build_catalog()
    assert _best_ms(lambda: c.select(CODING_AGENT_TOOLSET)) < 5.0


def test_flow_analysis_of_full_catalog_under_25ms():
    c = build_catalog()
    ts = c.toolset(set(c.tools))
    assert _best_ms(lambda: analyze_toolset(ts)) < 25.0


def test_drift_check_under_10ms():
    c = build_catalog()
    assert _best_ms(lambda: c.drift("filesystem", {"read_file", "write_file", "ghost"})) < 10.0


def test_policy_decision_under_10ms():
    # Engine construction parses once; a single decision must stay cheap.
    eng = CedarPolicyEngine(BASIC_CEDAR)
    c = build_catalog()
    tool = c.get("filesystem", "read_file")
    assert _best_ms(lambda: eng.decide(Principal("a"), tool, {})) < 10.0
