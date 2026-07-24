"""Unit tests for the in-process ``_RateLimiter`` — no socket, no loopback, so these
run even under the offline gate variant where ``test_auth`` self-skips."""

from __future__ import annotations

from toolconnect.server import _RateLimiter


def test_idle_keys_are_evicted_so_hits_stays_bounded():
    """A key is only trimmed when re-checked, so a client that bursts once and never
    returns must not leave its deque in ``_hits`` forever. Once a full window has
    elapsed, the periodic sweep drops the aged-out keys."""
    lim = _RateLimiter(per_window=5, window_seconds=60.0)
    for i in range(100):
        # 100 distinct clients each send one request at t=0.
        assert lim.check(f"ip-{i}", now=0.0)[0] is True
    assert len(lim._hits) == 100
    # Long after the window, one active client checks in. The sweep must evict the
    # 100 idle keys, leaving only the active one — O(active clients), not O(all-time).
    lim.check("late", now=1000.0)
    assert len(lim._hits) == 1
    assert set(lim._hits) == {"late"}


def test_active_key_survives_the_sweep():
    """Eviction must not drop a key that is still within its window."""
    lim = _RateLimiter(per_window=5, window_seconds=60.0)
    lim.check("ip-a", now=0.0)
    # A second client 100 s later triggers a sweep; "ip-a" is idle and evicted, but a
    # third request from a client active near "now" is retained.
    lim.check("ip-b", now=100.0)
    lim.check("ip-b", now=100.5)
    assert "ip-a" not in lim._hits
    assert "ip-b" in lim._hits and len(lim._hits["ip-b"]) == 2
