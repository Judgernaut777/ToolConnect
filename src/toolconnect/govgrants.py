"""Connect-Governance execution-grant verification — vendored, pure, offline.

This module is ToolConnect's side of the R5 redemption contract
(``docs/REDEMPTION_CONTRACT.md`` in Connect-Governance): a caller presents an
execution grant issued by Connect-Governance, and ToolConnect verifies it
locally against a configured trust root — no network, no filesystem, no clock,
no import of any governance package. The repos interoperate through the
artifact (canonical JSON + Ed25519 signature + key id), and byte-compatibility
is proven by a contract test over the governance conformance vectors
(``tests/test_govgrant_vectors.py``), not by shared code.

Determinism: every instant the verifier needs is supplied by the caller
(``at=``). Nothing here reads a wall clock, and Ed25519 verification is itself
deterministic, so the same grant + key + instant always yields the same result
— which is what makes a recorded verification replayable.

Fail closed: every structural or cryptographic problem is reported as a result
carrying stable ``failure_codes``; this module never raises on attacker input.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

#: Wire-format versions of the grant artifact this verifier understands.
SUPPORTED_FORMAT_VERSIONS = frozenset({"1"})
SIGNATURE_SCHEME = "Ed25519"

#: The operation a ToolConnect tool invocation maps to in grant scope.
INVOKE_OPERATION = "tool.invoke"

#: Fields the payload MUST carry for ToolConnect to even consider redemption.
#: Anything missing or wrongly typed is ``malformed_grant`` — a verifier at the
#: point of effect must never guess at the shape of its authorization.
REQUIRED_PAYLOAD_FIELDS: Mapping[str, type | tuple[type, ...]] = {
    "grant_format_version": str,
    "grant_id": str,
    "decision_record_id": str,
    "work_request_id": str,
    "requesting_principal_id": str,
    "organization_id": str,
    "workspace_id": str,
    "provider_id": str,
    "permitted_operations": list,
    "argument_constraints": dict,
    "data_classifications": list,
    "policy_versions": list,
    "kernel_version": str,
    "issued_at": str,
    "issuer_key_id": str,
}
OPTIONAL_PAYLOAD_FIELDS: Mapping[str, type | tuple[type, ...]] = {
    "work_request_revision": (str, type(None)),
    "budget_limit_usd": ((int, float), type(None)),
    "delegation_depth": int,
    "delegation_max_depth": (int, type(None)),
    "not_before": (str, type(None)),
    "not_after": (str, type(None)),
    "revocation_state": (str, type(None)),
    "correlation_id": (str, type(None)),
}


@dataclass(frozen=True)
class GovVerification:
    """Structured verification outcome — evidence for the enforcement record."""

    valid: bool
    signature_valid: bool
    within_validity_window: bool
    failure_codes: tuple[str, ...] = ()
    issuer_key_id: str | None = None
    payload: Mapping[str, Any] | None = field(default=None, compare=False)


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    """The exact bytes the signature covers, per the governance canonical rule:
    UTF-8, keys sorted by code point, no insignificant whitespace, non-ASCII
    emitted literally. NaN/Infinity are rejected — they are not JSON.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def public_key_id(public_key_pem: str) -> str:
    """The governance key id: ``ed25519:`` + sha256 of the raw public key."""
    key = load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("governance trust roots must be Ed25519 keys")
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _parse_rfc3339(value: str) -> datetime:
    text = value.strip()
    if text.endswith(("z", "Z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must carry a UTC offset: {value!r}")
    return parsed


def _structural_failures(grant: Any) -> tuple[list[str], Mapping[str, Any] | None]:
    """Shape checks, all fail-closed. Returns (failures, payload-or-None)."""
    if not isinstance(grant, Mapping):
        return ["malformed_grant"], None
    payload = grant.get("payload")
    scheme = grant.get("signature_scheme")
    signature = grant.get("signature")
    if not isinstance(payload, Mapping) or not isinstance(scheme, str) \
            or not isinstance(signature, str):
        return ["malformed_grant"], None
    failures: list[str] = []
    if scheme != SIGNATURE_SCHEME:
        failures.append("unsupported_scheme")
    fmt = payload.get("grant_format_version")
    if not isinstance(fmt, str) or fmt not in SUPPORTED_FORMAT_VERSIONS:
        failures.append("unsupported_format")
        return failures + ["malformed_grant"], None
    for name, types in REQUIRED_PAYLOAD_FIELDS.items():
        if name not in payload or not isinstance(payload[name], types) \
                or (types is str and not payload[name]):
            failures.append("malformed_grant")
            break
    else:
        for name, types in OPTIONAL_PAYLOAD_FIELDS.items():
            if name in payload and not isinstance(payload[name], types):
                failures.append("malformed_grant")
                break
    if failures:
        return failures, None
    return failures, payload


def verify_grant(grant: Any, public_key_pem: str | None, *, at: str,
                 expected_key_id: str | None = None) -> GovVerification:
    """Verify a governance execution grant. Pure; ``at`` is the caller's instant.

    ``public_key_pem`` is the configured governance trust root. ``None`` means
    the provider has no trust root configured at all — the most basic fail
    closed: ``missing_trust_root``. ``expected_key_id`` pins the issuer the
    caller requires (e.g. a pre-rotation key): a mismatch fails closed with
    ``key_id_mismatch``, exactly as Connect-Governance's verifier reports it.
    """
    failures, payload = _structural_failures(grant)
    if payload is None:
        return GovVerification(False, False, False, tuple(failures))

    issuer_key_id = payload["issuer_key_id"]
    if expected_key_id is not None and issuer_key_id != expected_key_id:
        failures.append("key_id_mismatch")

    if public_key_pem is None:
        return GovVerification(False, False, False,
                               tuple(failures + ["missing_trust_root"]),
                               issuer_key_id=issuer_key_id, payload=payload)

    signature_valid = False
    try:
        key = load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            failures.append("missing_trust_root")  # unusable configured root
        elif public_key_id(public_key_pem) != issuer_key_id:
            # The grant names an issuer this trust root is not. Distinguish
            # "unknown issuer" (key rotation, wrong deployment) from a broken
            # signature — different operational responses.
            failures.append("unknown_issuer")
        elif "unsupported_scheme" not in failures:
            key.verify(_b64d(grant["signature"]), canonical_payload_bytes(payload))
            signature_valid = True
    except (InvalidSignature, ValueError):
        if not any(f in failures for f in ("unknown_issuer", "missing_trust_root")):
            failures.append("signature_mismatch")

    within_window = True
    try:
        t = _parse_rfc3339(at)
        if payload["not_before"] is not None and t < _parse_rfc3339(payload["not_before"]):
            within_window = False
            failures.append("not_yet_valid")
        if payload["not_after"] is not None and t >= _parse_rfc3339(payload["not_after"]):
            within_window = False
            failures.append("expired")
    except ValueError:
        within_window = False
        failures.append("malformed_grant")

    valid = signature_valid and within_window and not failures
    return GovVerification(valid, signature_valid, within_window,
                           tuple(failures), issuer_key_id=issuer_key_id,
                           payload=payload)


def scope_failures(payload: Mapping[str, Any], *, principal_id: str,
                   provider_id: str, source_id: str, name: str,
                   args: Mapping[str, Any]) -> tuple[str, ...]:
    """Bind grant scope to this authorization request. Pure; fail closed.

    The binding rule (REDEMPTION_CONTRACT.md):

    * ``provider_id`` must be this provider;
    * ``permitted_operations`` must include ``tool.invoke``;
    * ``requesting_principal_id`` must be the calling principal;
    * ``argument_constraints["tool"]`` must be present and equal the tool name
      — a grant for another tool is not a grant for this one;
    * ``argument_constraints["source"]``, when the issuer constrained it, must
      equal the source id;
    * every other constraint key must equal the corresponding value in
      ``args`` (exact JSON equality).
    """
    failures: list[str] = []
    if payload["provider_id"] != provider_id:
        failures.append("provider_mismatch")
    if INVOKE_OPERATION not in payload["permitted_operations"]:
        failures.append("operation_not_permitted")
    if payload["requesting_principal_id"] != principal_id:
        failures.append("principal_mismatch")
    constraints = payload["argument_constraints"]
    if constraints.get("tool") != name or (
            "source" in constraints and constraints["source"] != source_id):
        failures.append("scope_mismatch")
    else:
        for key, expected in constraints.items():
            if key in ("tool", "source"):
                continue
            if key not in args or args[key] != expected:
                failures.append("args_mismatch")
                break
    return tuple(failures)


__all__ = [
    "GovVerification",
    "INVOKE_OPERATION",
    "SIGNATURE_SCHEME",
    "SUPPORTED_FORMAT_VERSIONS",
    "canonical_payload_bytes",
    "public_key_id",
    "scope_failures",
    "verify_grant",
]
