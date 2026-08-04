"""Governance execution-grant redemption (R5): adversarial service-level tests.

Every branch fails closed, and every failure is itself a Provider Enforcement
Record on the hash-chained audit. Grants in these tests are minted with real
Ed25519 keys via `cryptography`, in the governance canonical form — the same
bytes Connect-Governance signs (byte-compat proven separately in
tests/test_govgrant_vectors.py against the governance conformance vectors).
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from toolconnect import govgrants
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import DECISION_CONTRACT_VERSION, ServiceError, ToolConnectService
from toolconnect.store import SqliteStore

AT = "2026-08-03T12:00:00Z"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    pub_pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return priv_pem, pub_pem


PRIV_PEM, PUB_PEM = _keypair()
OTHER_PRIV_PEM, OTHER_PUB_PEM = _keypair()
KEY_ID = govgrants.public_key_id(PUB_PEM)


def mint_grant(priv_pem: str = PRIV_PEM, **payload_overrides) -> dict:
    """Sign a grant exactly as Connect-Governance does: canonical JSON, Ed25519."""
    payload: dict[str, Any] = {
        "grant_format_version": "1",
        "grant_id": "g-1",
        "decision_record_id": "dr-1",
        "work_request_id": "wr-1",
        "work_request_revision": "rev-1",
        "requesting_principal_id": "agent-1",
        "organization_id": "org-1",
        "workspace_id": "ws-1",
        "provider_id": "toolconnect",
        "permitted_operations": ["tool.invoke"],
        "argument_constraints": {"tool": "reader", "source": "s",
                                 "path": "/srv/in"},
        "data_classifications": ["internal"],
        "budget_limit_usd": None,
        "delegation_depth": 0,
        "delegation_max_depth": None,
        "policy_versions": ["pol-1@3"],
        "kernel_version": "0.0.1",
        "not_before": "2026-08-03T00:00:00Z",
        "not_after": "2026-08-04T00:00:00Z",
        "revocation_state": "active",
        "issued_at": AT,
        "issuer_key_id": KEY_ID,
        "correlation_id": "corr-1",
    }
    payload.update(payload_overrides)
    signed = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False).encode()
    priv = load_pem_private_key(priv_pem.encode(), password=None)
    sig = base64.urlsafe_b64encode(priv.sign(signed)).decode().rstrip("=")
    return {"payload": payload, "signature_scheme": "Ed25519", "signature": sig}


@pytest.fixture()
def service(tmp_path):
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(store, CedarPolicyEngine(""),
                             gov_trust_root_pem=PUB_PEM)
    yield svc
    store.close()


def redeem(service, grant, **kw):
    params = dict(principal={"id": "agent-1"}, source_id="s", name="reader",
                  args={"path": "/srv/in"}, at=AT)
    params.update(kw)
    return service.redeem_governance_grant(grant, **params)


class TestHappyPath:
    def test_valid_grant_redeems(self, service):
        r = redeem(service, mint_grant())
        assert r["redeemed"] is True and r["reason"] == "ok"
        assert r["decision_record_id"] == "dr-1"
        assert r["correlation_id"] == "corr-1"
        assert r["contract_version"] == DECISION_CONTRACT_VERSION

    def test_provider_enforcement_record_written_and_stored(self, service):
        r = redeem(service, mint_grant())
        records = service.read_audit(kind="provider_enforcement")
        assert len(records) == 1
        body = records[0]["body"]
        assert body["grant_id"] == "g-1"
        assert body["decision_record_id"] == "dr-1"
        assert body["correlation_id"] == "corr-1"
        assert body["issuer_key_id"] == KEY_ID
        assert body["provider_id"] == "toolconnect"
        assert body["principal_id"] == "agent-1"
        assert body["verified"] is True
        assert body["outcome"] == "redeemed"
        assert body["args_hash"] and body["redeemed_at"]
        # The one-use claim is durable in the redemptions table.
        row = service.store.get_govgrant_redemption("g-1")
        assert row is not None and row["decision_record_id"] == "dr-1"

    def test_audit_chain_intact_after_redemptions(self, service):
        for i in range(5):
            redeem(service, mint_grant(grant_id=f"g-{i}"))
        assert service.verify_audit()["ok"] is True
        assert len(service.read_audit(kind="provider_enforcement")) == 5


class TestAdversarial:
    def test_replay_denied(self, service):
        grant = mint_grant()
        assert redeem(service, grant)["redeemed"] is True
        r = redeem(service, grant)
        assert r["redeemed"] is False and r["reason"] == "already_redeemed"
        # The replay denial is itself recorded; only ONE redemption row exists.
        bodies = [rec["body"] for rec in service.read_audit(kind="provider_enforcement")]
        assert [b["outcome"] for b in bodies] == ["denied:already_redeemed", "redeemed"]
        assert service.store.get_govgrant_redemption("g-1")["redeemed_at"]

    def test_tampered_payload_denied(self, service):
        grant = mint_grant()
        grant["payload"]["argument_constraints"]["path"] = "/etc/passwd"
        r = redeem(service, grant)
        assert r["redeemed"] is False and r["reason"] == "signature_mismatch"
        body = service.read_audit(kind="provider_enforcement")[0]["body"]
        assert body["verified"] is False
        assert body["outcome"] == "denied:signature_mismatch"
        assert service.store.get_govgrant_redemption("g-1") is None

    def test_tampered_signature_denied(self, service):
        grant = mint_grant()
        grant["signature"] = grant["signature"][:-2] + ("AA" if grant["signature"][-2:] != "AA" else "BB")
        r = redeem(service, grant)
        assert r["redeemed"] is False and r["reason"] == "signature_mismatch"

    @pytest.mark.parametrize("nb,na,reason", [
        ("2026-08-04T00:00:00Z", "2026-08-05T00:00:00Z", "not_yet_valid"),
        ("2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z", "expired"),
        ("2026-08-01T00:00:00Z", AT, "expired"),  # half-open: t == not_after is out
    ])
    def test_validity_window_enforced(self, service, nb, na, reason):
        r = redeem(service, mint_grant(not_before=nb, not_after=na))
        assert r["redeemed"] is False and r["reason"] == reason

    def test_wrong_key_denied_as_unknown_issuer(self, service):
        # Signed by a key the configured trust root does not name, and honestly
        # naming that key as its issuer: the trust root is not this issuer.
        r = redeem(service, mint_grant(
            priv_pem=OTHER_PRIV_PEM,
            issuer_key_id=govgrants.public_key_id(OTHER_PUB_PEM)))
        assert r["redeemed"] is False and r["reason"] == "unknown_issuer"

    def test_forged_key_attribution_denied(self, service):
        # Signed by a stranger's key but CLAIMING the trusted issuer's key id:
        # attribution forgery must fail the signature, not pass attribution.
        r = redeem(service, mint_grant(priv_pem=OTHER_PRIV_PEM))
        assert r["redeemed"] is False and r["reason"] == "signature_mismatch"

    def test_missing_trust_root_denied(self, tmp_path):
        store = SqliteStore(tmp_path / "tc.db")
        svc = ToolConnectService(store, CedarPolicyEngine(""))  # no trust root
        try:
            r = redeem(svc, mint_grant())
            assert r["redeemed"] is False and r["reason"] == "missing_trust_root"
            body = svc.read_audit(kind="provider_enforcement")[0]["body"]
            assert body["outcome"] == "denied:missing_trust_root"
        finally:
            store.close()

    @pytest.mark.parametrize("override,reason", [
        ({"provider_id": "evilconnect"}, "provider_mismatch"),
        ({"permitted_operations": ["tool.delete"]}, "operation_not_permitted"),
        ({"requesting_principal_id": "agent-2"}, "principal_mismatch"),
        ({"argument_constraints": {"tool": "writer", "source": "s"}},
         "scope_mismatch"),
        ({"argument_constraints": {"tool": "reader", "source": "other"}},
         "scope_mismatch"),
        ({"argument_constraints": {"tool": "reader", "source": "s",
                                   "path": "/etc/shadow"}}, "args_mismatch"),
    ])
    def test_scope_binding_denies(self, service, override, reason):
        r = redeem(service, mint_grant(**override))
        assert r["redeemed"] is False and r["reason"] == reason
        assert service.store.get_govgrant_redemption("g-1") is None

    def test_wrong_presented_args_denied(self, service):
        r = redeem(service, mint_grant(), args={"path": "/tmp/other"})
        assert r["redeemed"] is False and r["reason"] == "args_mismatch"

    @pytest.mark.parametrize("bad_grant", [
        None, "not a grant", [], {},
        {"payload": {}, "signature_scheme": "Ed25519", "signature": "x"},
        {"payload": mint_grant()["payload"], "signature_scheme": "RSA",
         "signature": "x"},
        {"payload": {**mint_grant()["payload"], "grant_format_version": "99"},
         "signature_scheme": "Ed25519", "signature": "x"},
    ])
    def test_malformed_grants_deny_never_raise(self, service, bad_grant):
        r = redeem(service, bad_grant)
        assert r["redeemed"] is False
        assert r["reason"] in ("malformed_grant", "unsupported_scheme",
                               "unsupported_format", "signature_mismatch")
        assert service.verify_audit()["ok"] is True

    def test_extra_grant_field_breaks_signature_not_verifier(self, service):
        # An unknown payload field is attacker-controlled content that must not
        # be silently accepted: canonical bytes change, so verification fails.
        grant = mint_grant()
        grant["payload"]["backdoor"] = True
        r = redeem(service, grant)
        assert r["redeemed"] is False and r["reason"] == "signature_mismatch"

    def test_args_validation_happens_before_any_audit_write(self, service):
        before = len(service.read_audit(limit=1000))
        with pytest.raises(ServiceError) as exc:
            redeem(service, mint_grant(), args="not an object")
        assert exc.value.status == 400
        assert len(service.read_audit(limit=1000)) == before

    def test_failed_verification_does_not_consume_one_use(self, service):
        """A scope failure leaves the grant unredeemed: a corrected retry succeeds."""
        grant = mint_grant()
        assert redeem(service, grant, args={"path": "/wrong"})["redeemed"] is False
        assert redeem(service, grant)["redeemed"] is True


class TestAtomicity:
    def test_one_use_under_concurrency(self, tmp_path):
        """Concurrent redemptions of the same grant: exactly one wins, and the
        audit chain stays intact (one redeemed record + N-1 denials)."""
        import threading
        store = SqliteStore(tmp_path / "tc.db")
        svc = ToolConnectService(store, CedarPolicyEngine(""),
                                 gov_trust_root_pem=PUB_PEM)
        try:
            grant = mint_grant()
            results = []
            lock = threading.Lock()

            def attempt(_):
                r = redeem(svc, grant)
                with lock:
                    results.append(r["redeemed"])

            threads = [threading.Thread(target=attempt, args=(i,))
                       for i in range(12)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert results.count(True) == 1
            assert results.count(False) == 11
            assert svc.verify_audit()["ok"] is True
            outcomes = sorted(rec["body"]["outcome"] for rec in
                              svc.read_audit(kind="provider_enforcement", limit=100))
            assert outcomes == ["denied:already_redeemed"] * 11 + ["redeemed"]
        finally:
            store.close()

    def test_audit_failure_rolls_back_one_use_claim(self, service, monkeypatch):
        """ADR 0002 §4: if the enforcement record cannot be written, the
        redemption must not become durable either."""
        def boom(kind, body):
            raise RuntimeError("disk full")
        monkeypatch.setattr(service.store, "_append_audit_in_txn", boom)
        with pytest.raises(RuntimeError):
            redeem(service, mint_grant())
        assert service.store.get_govgrant_redemption("g-1") is None
        # Retry without the fault: the grant is still redeemable — it was not
        # half-consumed by the rolled-back attempt.
        monkeypatch.undo()
        assert redeem(service, mint_grant())["redeemed"] is True
