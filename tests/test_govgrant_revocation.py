"""ADR-052 revocation-list propagation (R7): verifier + service + CLI tests.

Revocation lists in these tests are signed with real Ed25519 keys in the
governance canonical form (UTF-8, sorted keys, no whitespace) over every field
except ``signature`` — the same bytes Connect-Governance signs, mirroring how
tests/test_govgrant_redemption.py mints grants.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path
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
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

from test_govgrant_redemption import AT, KEY_ID, PRIV_PEM, PUB_PEM, mint_grant

REPO = Path(__file__).resolve().parent.parent

LIST_ISSUED_AT = "2026-08-03T06:00:00Z"  # before AT (noon) and before the
# default mint_grant issued_at (noon) — the DEFAULT list is therefore STALE
# for default grants; freshness-sensitive tests use fresh_grant() below.


def fresh_grant(**overrides):
    """A grant minted BEFORE the default list (issued 06:00): non-stale."""
    overrides.setdefault("issued_at", "2026-08-03T00:00:00Z")
    return mint_grant(**overrides)


def mint_revocation_list(priv_pem: str = PRIV_PEM, **overrides) -> dict:
    """Sign an ADR-052 revocation list exactly as Connect-Governance does."""
    doc: dict[str, Any] = {
        "revocation_list_format_version": "1",
        "issuer_key_id": KEY_ID,
        "issued_at": LIST_ISSUED_AT,
        "revoked_grant_ids": [],
        "supersedes": None,
        "list_id": "rl-1",
        "signature_scheme": "Ed25519",
    }
    doc.update(overrides)
    signed = json.dumps(doc, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False).encode()
    priv = load_pem_private_key(priv_pem.encode(), password=None)
    doc["signature"] = base64.urlsafe_b64encode(priv.sign(signed)).decode().rstrip("=")
    return doc


@pytest.fixture()
def listed_service(tmp_path):
    """A service holding a fresh, authentic revocation list (postdates grants)."""
    store = SqliteStore(tmp_path / "tc.db")
    svc = ToolConnectService(
        store, CedarPolicyEngine(""), gov_trust_root_pem=PUB_PEM,
        gov_revocation_list=mint_revocation_list())  # issued 06:00, at is noon
    yield svc
    store.close()


def redeem(service, grant, **kw):
    params = dict(principal={"id": "agent-1"}, source_id="s", name="reader",
                  args={"path": "/srv/in"}, at=AT)
    params.update(kw)
    return service.redeem_governance_grant(grant, **params)


class TestVerifyRevocationList:
    def test_round_trip_valid_list(self):
        assert govgrants.verify_revocation_list(
            mint_revocation_list(), PUB_PEM, at=AT) == ()

    def test_missing_list(self):
        assert govgrants.verify_revocation_list(None, PUB_PEM, at=AT) == (
            "missing_revocation_list",)

    @pytest.mark.parametrize("bad", ["not a list", 42, []])
    def test_non_mapping_list(self, bad):
        assert govgrants.verify_revocation_list(bad, PUB_PEM, at=AT) == (
            "malformed_revocation_list",)

    def test_tampered_list_denied(self):
        doc = mint_revocation_list()
        doc["revoked_grant_ids"] = ["g-1"]  # after signing
        codes = govgrants.verify_revocation_list(doc, PUB_PEM, at=AT)
        assert "signature_mismatch" in codes

    def test_wrong_issuer_key(self):
        doc = mint_revocation_list(
            issuer_key_id="ed25519:" + "0" * 64)  # not the trust root's id
        assert "unknown_issuer" in govgrants.verify_revocation_list(
            doc, PUB_PEM, at=AT)

    def test_no_trust_root(self):
        assert "missing_trust_root" in govgrants.verify_revocation_list(
            mint_revocation_list(), None, at=AT)

    def test_unsupported_format(self):
        codes = govgrants.verify_revocation_list(
            mint_revocation_list(revocation_list_format_version="99"),
            PUB_PEM, at=AT)
        assert "unsupported_format" in codes and "malformed_revocation_list" in codes

    def test_future_list_not_yet_valid(self):
        codes = govgrants.verify_revocation_list(
            mint_revocation_list(issued_at="2026-08-03T18:00:00Z"),
            PUB_PEM, at="2026-08-03T12:00:00Z")
        assert "not_yet_valid" in codes


class TestVerifyGrantRevocation:
    def test_revoked_grant_denied(self):
        doc = mint_revocation_list(revoked_grant_ids=["g-1"])
        v = govgrants.verify_grant(fresh_grant(), PUB_PEM, at=AT,
                                   revocation_list=doc)
        assert not v.valid and "revoked" in v.failure_codes

    def test_unrelated_grant_redeems_with_list(self):
        doc = mint_revocation_list(revoked_grant_ids=["someone-else"])
        v = govgrants.verify_grant(fresh_grant(), PUB_PEM, at=AT,
                                   revocation_list=doc)
        assert v.valid, v.failure_codes

    def test_stale_list_denies_overlapping_grant(self):
        # List issued BEFORE the grant was minted: it cannot attest to g-1.
        doc = mint_revocation_list()  # issued 06:00, grant issued at noon
        v = govgrants.verify_grant(mint_grant(), PUB_PEM, at=AT,
                                   revocation_list=doc)
        assert not v.valid and "stale_revocation_list" in v.failure_codes

    def test_stale_list_ignores_non_overlapping_grant(self):
        # Grant whose window ended BEFORE the (stale) list existed: staleness
        # must not deny it — the grant stands or falls on its own window.
        doc = mint_revocation_list(issued_at="2026-08-02T00:00:00Z")
        grant = mint_grant(issued_at="2026-08-01T00:00:00Z",
                           not_before="2026-08-01T00:00:00Z",
                           not_after="2026-08-01T12:00:00Z")
        v = govgrants.verify_grant(grant, PUB_PEM, at="2026-08-01T06:00:00Z",
                                   revocation_list=doc)
        assert v.valid, v.failure_codes

    def test_missing_list_code_is_overlap_gated(self):
        # A non-document ("the list is missing") fails closed only for grants
        # whose windows overlap any plausible coverage — here the broken doc
        # carries no usable issued_at, so it denies the overlapping grant...
        v = govgrants.verify_grant(mint_grant(), PUB_PEM, at=AT,
                                   revocation_list={})
        assert not v.valid and "malformed_revocation_list" in v.failure_codes
        # ...and verify_revocation_list reports the missing case for callers
        # that mandate a list, without touching verify_grant's legacy mode.
        assert "missing_revocation_list" in govgrants.verify_revocation_list(
            None, PUB_PEM, at=AT)

    def test_none_list_preserves_r5_behavior(self):
        grant = mint_grant()
        legacy = govgrants.verify_grant(grant, PUB_PEM, at=AT)
        explicit = govgrants.verify_grant(grant, PUB_PEM, at=AT,
                                          revocation_list=None)
        assert legacy == explicit
        assert legacy.valid and legacy.failure_codes == ()


class TestServiceRevocation:
    def test_revoked_denial_recorded_as_provider_enforcement(self, listed_service):
        svc = listed_service
        svc.gov_revocation_list = mint_revocation_list(revoked_grant_ids=["g-1"])
        r = redeem(svc, fresh_grant())
        assert r["redeemed"] is False and r["reason"] == "revoked"
        assert "revoked" in r["failure_codes"]
        body = svc.read_audit(kind="provider_enforcement")[0]["body"]
        assert body["outcome"] == "denied:revoked"
        assert body["verified"] is False
        assert "revoked" in body["failure_codes"]
        assert svc.store.get_govgrant_redemption("g-1") is None
        assert svc.verify_audit()["ok"] is True

    def test_list_loaded_grants_still_redeem(self, listed_service):
        r = redeem(listed_service, fresh_grant())
        assert r["redeemed"] is True, r

    def test_stale_list_denies_at_service(self, tmp_path):
        store = SqliteStore(tmp_path / "tc.db")
        svc = ToolConnectService(store, CedarPolicyEngine(""),
                                 gov_trust_root_pem=PUB_PEM,
                                 gov_revocation_list=mint_revocation_list())
        try:
            r = redeem(svc, mint_grant())  # grant issued after the list
            assert r["redeemed"] is False and r["reason"] == "stale_revocation_list"
            body = svc.read_audit(kind="provider_enforcement")[0]["body"]
            assert body["outcome"] == "denied:stale_revocation_list"
        finally:
            store.close()

    def test_non_overlapping_grant_redeems_despite_stale_list(self, tmp_path):
        store = SqliteStore(tmp_path / "tc.db")
        svc = ToolConnectService(
            store, CedarPolicyEngine(""), gov_trust_root_pem=PUB_PEM,
            gov_revocation_list=mint_revocation_list(
                issued_at="2026-08-02T00:00:00Z"))
        try:
            grant = mint_grant(grant_id="g-old", issued_at="2026-08-01T00:00:00Z",
                               not_before="2026-08-01T00:00:00Z",
                               not_after="2026-08-01T12:00:00Z")
            r = redeem(svc, grant, at="2026-08-01T06:00:00Z")
            assert r["redeemed"] is True, r
        finally:
            store.close()

    def test_no_list_configured_is_legacy_r5(self, tmp_path):
        store = SqliteStore(tmp_path / "tc.db")
        svc = ToolConnectService(store, CedarPolicyEngine(""),
                                 gov_trust_root_pem=PUB_PEM)
        try:
            assert redeem(svc, mint_grant())["redeemed"] is True
        finally:
            store.close()

    def test_list_identity_in_meta_and_health(self, listed_service):
        svc = listed_service
        assert svc.store.get_meta("gov_revocation_list_id") == "rl-1"
        assert svc.store.get_meta("gov_revocation_list_issued_at") == LIST_ISSUED_AT
        health = svc.health()
        assert health["gov_revocation_list"] == {
            "list_id": "rl-1", "issued_at": LIST_ISSUED_AT}

    def test_health_reports_no_list_in_legacy_mode(self, tmp_path):
        store = SqliteStore(tmp_path / "tc.db")
        svc = ToolConnectService(store, CedarPolicyEngine(""))
        try:
            assert svc.health()["gov_revocation_list"] is None
        finally:
            store.close()


class TestCliGovernanceWiring:
    """The governance trust material must reach the service from the CLI —
    before R7 the trust root had no CLI seam at all."""

    def _run(self, *args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
        import os
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), **(env_extra or {})}
        return subprocess.run([sys.executable, "-m", "toolconnect.cli", *args],
                              capture_output=True, text=True, env=env)

    def test_missing_trust_root_file_refused(self, tmp_path):
        policies = tmp_path / "ok.cedar"
        policies.write_text("")
        out = self._run("serve", "--db", str(tmp_path / "tc.db"),
                        "--policies", str(policies),
                        "--gov-trust-root", str(tmp_path / "nope.pem"))
        assert out.returncode != 0
        assert "trust root not found" in out.stderr + out.stdout

    def test_missing_revocation_list_file_refused(self, tmp_path):
        policies = tmp_path / "ok.cedar"
        policies.write_text("")
        out = self._run("serve", "--db", str(tmp_path / "tc.db"),
                        "--policies", str(policies),
                        "--gov-revocation-list", str(tmp_path / "nope.json"))
        assert out.returncode != 0
        assert "revocation list not found" in out.stderr + out.stdout

    def test_flags_parse_on_all_service_subcommands(self):
        for sub in ("serve", "gateway", "ingest-openapi"):
            out = self._run(sub, "--help")
            assert out.returncode == 0
            assert "--gov-trust-root" in out.stdout
            assert "--gov-revocation-list" in out.stdout

    def test_env_fallback_loads_trust_root_and_list(self, tmp_path, monkeypatch):
        # Unit-level: _load_governance precedence flag > env > config > None.
        import argparse
        from toolconnect import cli
        pem = tmp_path / "root.pem"
        pem.write_text(PUB_PEM)
        doc = tmp_path / "list.json"
        doc.write_text(json.dumps(mint_revocation_list()))
        monkeypatch.setenv("TOOLCONNECT_GOV_TRUST_ROOT", str(pem))
        monkeypatch.setenv("TOOLCONNECT_GOV_REVOCATION_LIST", str(doc))
        args = argparse.Namespace(gov_trust_root=None, gov_revocation_list=None)
        trust_root_pem, revocation_list = cli._load_governance(args, {})
        assert trust_root_pem == PUB_PEM
        assert revocation_list["list_id"] == "rl-1"
        # Explicit flag beats env.
        other_pem = tmp_path / "other.pem"
        other_pem.write_text("flag pem")
        args = argparse.Namespace(gov_trust_root=str(other_pem),
                                  gov_revocation_list=None)
        trust_root_pem, _ = cli._load_governance(args, {})
        assert trust_root_pem == "flag pem"
        # Nothing configured: legacy R5 posture.
        monkeypatch.delenv("TOOLCONNECT_GOV_TRUST_ROOT")
        monkeypatch.delenv("TOOLCONNECT_GOV_REVOCATION_LIST")
        args = argparse.Namespace(gov_trust_root=None, gov_revocation_list=None)
        assert cli._load_governance(args, {}) == (None, None)
