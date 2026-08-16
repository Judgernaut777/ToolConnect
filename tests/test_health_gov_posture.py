"""R8: /health surfaces governance trust-root posture (provider classification).

A control plane can only honestly classify a provider as "enforcing" over HTTP
if /health attests that a governance trust root is configured (``gov_trust_root
.configured == true``) — key ids only, never the PEM — and names the provider
id. Additive fields; the decision contract version does not bump.
"""

from __future__ import annotations

from toolconnect import govgrants
from toolconnect.policy import CedarPolicyEngine
from toolconnect.service import ToolConnectService
from toolconnect.store import SqliteStore

from test_govgrant_redemption import PUB_PEM


def _service(tmp_path, **kwargs):
    store = SqliteStore(tmp_path / "tc.db")
    return store, ToolConnectService(store, CedarPolicyEngine(""), **kwargs)


class TestHealthTrustRootPosture:
    def test_trust_root_present_reports_key_ids(self, tmp_path):
        store, svc = _service(tmp_path, gov_trust_root_pem=PUB_PEM)
        try:
            health = svc.health()
            assert health["gov_trust_root"] == {
                "configured": True,
                "key_ids": [govgrants.public_key_id(PUB_PEM)],
            }
            # The PEM itself must never leak into the health surface.
            assert PUB_PEM not in str(health)
        finally:
            store.close()

    def test_trust_root_absent_reports_configured_false(self, tmp_path):
        store, svc = _service(tmp_path)
        try:
            health = svc.health()
            # The key is always present — never omitted — so a control plane
            # can distinguish "no trust root" from "old server".
            assert health["gov_trust_root"] == {
                "configured": False, "key_ids": []}
        finally:
            store.close()

    def test_provider_id_is_surfaced(self, tmp_path):
        store, svc = _service(tmp_path, gov_trust_root_pem=PUB_PEM,
                              gov_provider_id="acme-provider")
        try:
            assert svc.health()["gov_provider_id"] == "acme-provider"
        finally:
            store.close()

    def test_provider_id_default(self, tmp_path):
        store, svc = _service(tmp_path)
        try:
            assert svc.health()["gov_provider_id"] == "toolconnect"
        finally:
            store.close()

    def test_existing_health_fields_unchanged(self, tmp_path):
        store, svc = _service(tmp_path, gov_trust_root_pem=PUB_PEM)
        try:
            health = svc.health()
            assert health["status"] == "ok"
            assert health["audit_chain_ok"] is True
            assert health["audit_records"] == 0
            assert health["sources"] == 0
            assert health["tools"] == 0
            # R7 field untouched: no revocation list loaded -> None.
            assert health["gov_revocation_list"] is None
            # Additive only: every pre-R8 key is still there.
            for key in ("status", "version", "contract_version", "sources",
                        "tools", "audit_records", "audit_chain_ok",
                        "gov_revocation_list"):
                assert key in health
        finally:
            store.close()
