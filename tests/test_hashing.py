"""The canonical-JSON args-hash rule (docs/SERVICE.md), pinned against the nasty cases.

This is the ONLY implementation of the rule (``toolconnect.hashing``); ToolConnect is
the sole hasher on both the issue and redeem paths, so no client anywhere ever needs to
reproduce it. These tests exist so a future edit to the rule breaks loudly here rather
than silently changing what argument-bound grants actually bind.
"""

from __future__ import annotations

import unicodedata

import pytest

from toolconnect.hashing import ArgsNotHashable, args_hash, canonical_args

# NFC ("cafe" + combined e-acute) vs NFD ("cafe" + base e + combining acute) forms of
# the same visible string, built programmatically to avoid embedding non-ASCII source
# literals that different editors/encodings could silently normalize away.
_BASE = "caf" + "é"  # NFC: e9 is the single precomposed codepoint
_NFC = unicodedata.normalize("NFC", _BASE)
_NFD = unicodedata.normalize("NFD", _BASE)


class TestCanonicalization:
    def test_key_order_insensitive_at_every_nesting_level(self):
        a = {"b": 1, "a": {"z": 1, "y": 2}}
        b = {"a": {"y": 2, "z": 1}, "b": 1}
        assert args_hash(a) == args_hash(b)

    def test_array_order_is_significant(self):
        assert args_hash({"xs": [1, 2, 3]}) != args_hash({"xs": [3, 2, 1]})

    def test_nfc_vs_nfd_differ_by_design(self):
        # No Unicode normalization is applied — documented non-goal, not a bug.
        assert _NFC != _NFD  # sanity: the two forms really are different code points
        assert args_hash({"name": _NFC}) != args_hash({"name": _NFD})

    def test_int_and_float_never_conflate(self):
        assert args_hash({"n": 1}) != args_hash({"n": 1.0})

    def test_string_and_int_never_conflate(self):
        assert args_hash({"n": "5"}) != args_hash({"n": 5})

    def test_non_ascii_is_stable_via_ensure_ascii(self):
        h1 = args_hash({"name": _NFC})
        h2 = args_hash({"name": _NFC})
        assert h1 == h2
        assert "\\u00e9" in canonical_args({"name": _NFC})

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_float_is_rejected(self, bad):
        with pytest.raises(ArgsNotHashable):
            args_hash({"n": bad})

    def test_non_string_object_key_is_rejected_and_never_collides(self):
        # Reachable only in-process (JSON object keys are always strings over the
        # wire) but must never silently collide with the string-keyed equivalent.
        with pytest.raises(ArgsNotHashable):
            canonical_args({1: "a"})  # type: ignore[dict-item]
        # The string-keyed sibling must hash cleanly.
        assert args_hash({"1": "a"})

    @pytest.mark.parametrize("bad", [b"bytes", {1, 2, 3}, object()])
    def test_unsupported_types_are_rejected(self, bad):
        with pytest.raises(ArgsNotHashable):
            args_hash({"v": bad})

    def test_non_mapping_args_is_rejected(self):
        with pytest.raises(ArgsNotHashable):
            args_hash([1, 2, 3])  # type: ignore[arg-type]

    def test_nested_list_of_dicts_checked_recursively(self):
        with pytest.raises(ArgsNotHashable):
            canonical_args({"items": [{"ok": 1}, {1: "bad"}]})  # type: ignore[dict-item]

    def test_bool_is_accepted_and_distinct_from_int(self):
        assert args_hash({"flag": True}) != args_hash({"flag": 1})

    def test_deterministic_across_calls(self):
        payload = {"path": "/etc/passwd", "mode": "r", "n": [1, 2, {"k": "v"}]}
        assert args_hash(payload) == args_hash(dict(payload))
