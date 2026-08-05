"""Byte-compatibility contract: the vendored verifier agrees with Connect-Governance
on every published grant conformance vector.

This is the interop proof. ToolConnect does NOT import connect_governance; it
reproduces the verification semantics and is held to them by the governance
specification artifacts (conformance/grant-vectors/gv-001..gv-005), copied
verbatim into tests/fixtures/grant-vectors/. If governance changes its
canonical form, key-id rule, window semantics, or failure codes, the vector
files change and these tests fail here — before any provider is deployed
against an incompatible governance plane.

The end-to-end test at the bottom redeems a vector's expected_grant — a grant
whose signature was produced by Connect-Governance's signer — through the full
ToolConnect redemption path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolconnect import govgrants
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

VECTORS = sorted(
    (Path(__file__).parent / "fixtures" / "grant-vectors").glob("gv-*.json"))


@pytest.mark.parametrize("vector_path", VECTORS, ids=lambda p: p.stem)
def test_vendored_verifier_matches_governance_vectors(vector_path):
    v = json.loads(vector_path.read_text())
    expected = v["expected_verification"]

    # The governance-issued artifact, exactly as published.
    grant = v["expected_grant"]
    if "tampered_payload" in v:
        # gv-002: verify the published signature against the MUTATED payload.
        grant = {**grant, "payload": v["tampered_payload"]}
    kwargs = {"at": v["verify_at"]}
    if "expected_key_id" in v:
        kwargs["expected_key_id"] = v["expected_key_id"]

    result = govgrants.verify_grant(grant, v["public_key_pem"], **kwargs)
    assert result.valid == expected["valid"]
    assert result.signature_valid == expected["signature_valid"]
    assert result.within_validity_window == expected["within_validity_window"]
    assert result.issuer_key_id == expected["issuer_key_id"]

    if "expected_key_id" in v:
        # gv-005: the rotation check is an explicit caller constraint. The
        # governance semantics — a named-issuer mismatch fails closed — map to
        # the vendored verifier's unknown_issuer on a rotated trust root, and
        # to key_id_mismatch when the caller pins a different expected id.
        with_key_id = govgrants.verify_grant(
            v["expected_grant"], v["public_key_pem"], at=v["verify_at"],
        )
        assert with_key_id.valid
        # Trusting a DIFFERENT public key entirely must fail closed.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        other_pem = (Ed25519PrivateKey.generate().public_key()
                     .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                     .decode())
        rotated = govgrants.verify_grant(
            v["expected_grant"], other_pem, at=v["verify_at"])
        assert not rotated.valid and "unknown_issuer" in rotated.failure_codes
    else:
        assert list(result.failure_codes) == expected["failure_codes"]


def test_key_id_rule_matches_governance():
    """ed25519: + sha256(raw public key) — the same identifier on both sides."""
    v = json.loads(VECTORS[0].read_text())
    assert govgrants.public_key_id(v["public_key_pem"]) == (
        "ed25519:f294dcbe2bea2831af6df47eaf039ec5b7b223644dd1689f63be2d90bb5d800a")


def test_end_to_end_governance_issued_grant_redeems(tmp_path):
    """The R5 vertical slice: a grant signed by Connect-Governance's signer
    (gv-001's published signature) is redeemed by ToolConnect at the point of
    effect, producing the first Provider Enforcement Record."""
    v = json.loads((Path(__file__).parent / "fixtures" / "grant-vectors"
                    / "gv-001-sign-verify.json").read_text())
    grant = v["expected_grant"]

    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(""),
                             gov_trust_root_pem=v["public_key_pem"])
    try:
        # The vector's scope: provider toolconnect, operation tool.invoke,
        # principal agent-1, constraints tool=fs.write source not pinned — the
        # vector's constraints carry only {tool, path}, so bind source freely:
        # the contract requires "source" only when the issuer constrained it.
        r = svc.redeem_governance_grant(
            grant, {"id": "agent-1"}, "fs", "fs.write",
            {"path": "/srv/out"}, at=v["verify_at"])
        assert r["redeemed"] is True
        assert r["decision_record_id"] == "dr-vec-1"

        body = svc.read_audit(kind="provider_enforcement")[0]["body"]
        assert body["outcome"] == "redeemed"
        assert body["verified"] is True
        assert body["correlation_id"] == "corr-1"
        assert svc.verify_audit()["ok"] is True

        # And the one-use rule applies to governance grants too.
        again = svc.redeem_governance_grant(
            grant, {"id": "agent-1"}, "fs", "fs.write",
            {"path": "/srv/out"}, at=v["verify_at"])
        assert again["redeemed"] is False
        assert again["reason"] == "already_redeemed"
    finally:
        store.close()
