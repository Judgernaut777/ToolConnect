"""A small, dependency-free client for a running ``toolconnect serve``.

This is the artifact deliverable 7 asks for: a clean, importable Python client that a
caller — AgentConnect above all — can adopt to talk to a ToolConnect decision point
over HTTP, without re-deriving the wire shapes or the fail-closed rules by hand.

Design constraints, all load-bearing:

* **Stdlib only.** Uses ``urllib``; ToolConnect already refuses to grow a web
  framework, and its client should not force one on the caller either.
* **Fail closed by construction.** :meth:`ToolConnectClient.authorize` returns a
  :class:`Decision` whose ``allowed`` is ``False`` unless the server explicitly said
  ``True``. A transport error, a non-200, or a malformed body raises
  :class:`ToolConnectUnavailable` — it never degrades to an allow. The caller decides
  whether unavailability is fatal (``required`` mode) or falls back to a cached pack
  (``advisory`` mode); the client never makes that call silently.
* **No invocation.** There is deliberately no ``invoke``/``call`` method. The client
  authorizes and records; the caller executes. This mirrors the service: ToolConnect is
  never in the data path.

Configuration surface (documented for the AgentConnect side in
``docs/AGENTCONNECT_CONTRACT.md``): ``base_url`` and an optional bearer ``token`` (sent
as ``Authorization: Bearer …`` when set), plus a request ``timeout``. Construct from a
mapping/env with :meth:`ToolConnectClient.from_config`.
"""

from __future__ import annotations

import copy
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

__all__ = [
    "ToolConnectClient",
    "ClientDecision",
    "ClientGrant",
    "ClientRedemption",
    "ToolConnectError",
    "ToolConnectUnavailable",
    "ToolConnectDenied",
    "GrantRedeemDenied",
]


class ToolConnectError(Exception):
    """Base class for every client-side failure."""


class ToolConnectUnavailable(ToolConnectError):
    """The decision point could not be reached or gave an unusable answer.

    A caller in ``required`` mode MUST treat this as a denial. The client raises it
    rather than returning an allow, so unavailability can never be mistaken for one.
    """


class ToolConnectDenied(ToolConnectError):
    """Raised by :meth:`ToolConnectClient.require` when a decision was a deny."""

    def __init__(self, decision: "ClientDecision") -> None:
        super().__init__(decision.reason or "denied")
        self.decision = decision


class GrantRedeemDenied(ToolConnectError):
    """Raised by :meth:`ToolConnectClient.governed_invoke` when redeem refused a grant."""

    def __init__(self, redemption: "ClientRedemption") -> None:
        super().__init__(redemption.reason or "grant redeem denied")
        self.redemption = redemption


@dataclass(frozen=True)
class ClientGrant:
    """The client-side view of an argument-bound one-use grant (contract 1.1)."""

    grant_id: str
    args_hash: str = ""
    expires_at: str = ""
    ttl_seconds: int = 0


@dataclass(frozen=True)
class ClientRedemption:
    """The client-side view of a ``/grants/{id}/redeem`` response."""

    redeemed: bool
    reason: str = ""
    grant_id: str = ""
    decision_id: str = ""
    source_id: str = ""
    name: str = ""
    contract_version: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ClientDecision:
    """The client-side view of a ToolConnect Decision.

    Mirrors the pinned wire shape (``docs/SERVICE.md`` → *The Decision shape*). The
    ``contract_version`` field lets a caller detect a server it does not understand and
    fail closed rather than misread a future shape.
    """

    allowed: bool
    reason: str
    decision_id: str = ""
    determining_policies: tuple[str, ...] = ()
    default_deny: bool = False
    errors: tuple[str, ...] = ()
    contract_version: str = ""
    grant: ClientGrant | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_default_deny(self) -> bool:
        return self.default_deny

    @classmethod
    def from_json(cls, body: Mapping[str, Any]) -> "ClientDecision":
        # Fail closed: anything we cannot read as an explicit allow is a deny.
        grant_raw = body.get("grant")
        grant = None
        if isinstance(grant_raw, dict):
            grant = ClientGrant(
                grant_id=str(grant_raw.get("grant_id", "")),
                args_hash=str(grant_raw.get("args_hash", "")),
                expires_at=str(grant_raw.get("expires_at", "")),
                ttl_seconds=int(grant_raw.get("ttl_seconds", 0) or 0),
            )
        return cls(
            allowed=bool(body.get("allowed", False)),
            reason=str(body.get("reason", "")),
            decision_id=str(body.get("decision_id", "")),
            determining_policies=tuple(body.get("determining_policies", ()) or ()),
            default_deny=bool(body.get("default_deny", False)),
            errors=tuple(str(e) for e in (body.get("errors", ()) or ())),
            contract_version=str(body.get("contract_version", "")),
            grant=grant,
            raw=dict(body),
        )


class ToolConnectClient:
    """A thin, fail-closed HTTP client for a ToolConnect decision point."""

    #: The decision contract version this client was written against. If a server
    #: announces a different MAJOR version, :meth:`authorize` fails closed.
    EXPECTED_CONTRACT_MAJOR = "1"

    def __init__(self, base_url: str, *, token: str | None = None,
                 timeout: float = 10.0) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.token = token or None
        self.timeout = timeout

    # -- construction -----------------------------------------------------------

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None = None,
                    *, env: Mapping[str, str] | None = None) -> "ToolConnectClient":
        """Build from a config mapping, with environment fallback.

        Precedence: explicit ``config`` keys > environment. Recognized keys/vars:

        * ``base_url`` / ``TOOLCONNECT_URL``   (required)
        * ``token``    / ``TOOLCONNECT_TOKEN`` (optional bearer token)
        * ``timeout``  / ``TOOLCONNECT_TIMEOUT`` (optional seconds, default 10)
        """
        config = dict(config or {})
        env = env if env is not None else os.environ
        base_url = config.get("base_url") or env.get("TOOLCONNECT_URL")
        if not base_url:
            raise ValueError(
                "ToolConnect base_url not configured (config['base_url'] or "
                "TOOLCONNECT_URL)")
        token = config.get("token") or env.get("TOOLCONNECT_TOKEN")
        timeout_raw = config.get("timeout") or env.get("TOOLCONNECT_TIMEOUT") or 10.0
        return cls(str(base_url), token=token, timeout=float(timeout_raw))

    # -- transport --------------------------------------------------------------

    def _request(self, method: str, path: str,
                 body: Mapping[str, Any] | None = None) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            # A structured error body still parses; a decision-shaped 200 does not
            # arrive here. 4xx/5xx are returned so callers can branch (e.g. 401).
            try:
                parsed = json.loads(exc.read() or b"null")
            except (json.JSONDecodeError, ValueError):
                parsed = None
            return exc.code, parsed
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise ToolConnectUnavailable(
                f"toolconnect unreachable at {url}: {exc}") from exc

    # -- read surface -----------------------------------------------------------

    def health(self) -> dict:
        status, body = self._request("GET", "/health")
        if status != 200 or not isinstance(body, dict):
            raise ToolConnectUnavailable(f"health returned {status}: {body!r}")
        return body

    def list_sources(self) -> list[dict]:
        return self._get_ok("/sources")["sources"]

    def list_catalog(self) -> list[dict]:
        return self._get_ok("/catalog")["tools"]

    def get_tool(self, source_id: str, name: str) -> dict:
        return self._get_ok(f"/catalog/{source_id}/{name}")

    def drift(self, source_id: str) -> dict:
        return self._get_ok(f"/drift/{source_id}")

    def verify_audit(self) -> dict:
        return self._get_ok("/audit/verify")

    def read_audit(self, kind: str | None = None, limit: int = 100) -> list[dict]:
        q = f"?limit={int(limit)}" + (f"&kind={kind}" if kind else "")
        return self._get_ok(f"/audit{q}")["records"]

    def _get_ok(self, path: str) -> Any:
        status, body = self._request("GET", path)
        if status != 200:
            raise ToolConnectUnavailable(f"GET {path} returned {status}: {body!r}")
        return body

    # -- decision surface -------------------------------------------------------

    def authorize(self, principal: Mapping[str, Any], source_id: str, name: str,
                  context: Mapping[str, Any] | None = None, *,
                  args: Mapping[str, Any] | None = None,
                  ttl_seconds: int | None = None) -> ClientDecision:
        """Ask whether ``principal`` may call ``(source_id, name)``.

        Returns a :class:`ClientDecision`. A *deny* is a normal return value with
        ``allowed=False`` — it is a decision, not an error. Only genuine
        unavailability (transport failure, a non-200, a body we cannot read, or a
        server on an incompatible contract major) raises
        :class:`ToolConnectUnavailable`. There is no path that returns ``allowed=True``
        on failure.

        When ``args`` is given (contract 1.1), the decision binds those exact final
        arguments: on allow, the server issues a one-use grant (``decision.grant``)
        that must be redeemed via :meth:`redeem` immediately before the call actually
        executes. ``ttl_seconds`` is meaningless without ``args`` and is rejected by
        the server if given without it.
        """
        body: dict[str, Any] = {
            "principal": dict(principal), "source_id": source_id, "name": name}
        if context is not None:
            body["context"] = dict(context)
        if args is not None:
            body["args"] = dict(args)
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        status, payload = self._request("POST", "/authorize", body)
        if status != 200 or not isinstance(payload, dict) or "allowed" not in payload:
            raise ToolConnectUnavailable(
                f"/authorize returned {status}: {payload!r}")
        decision = ClientDecision.from_json(payload)
        major = (decision.contract_version or "0").split(".", 1)[0]
        if decision.contract_version and major != self.EXPECTED_CONTRACT_MAJOR:
            raise ToolConnectUnavailable(
                f"server decision contract v{decision.contract_version} is "
                f"incompatible with client-expected major "
                f"{self.EXPECTED_CONTRACT_MAJOR}")
        return decision

    def require(self, principal: Mapping[str, Any], source_id: str, name: str,
                context: Mapping[str, Any] | None = None) -> ClientDecision:
        """Like :meth:`authorize`, but raise :class:`ToolConnectDenied` on a deny.

        Convenience for ``required``-mode callers that want a single try/except around
        both "unreachable" and "denied" — both are reasons not to proceed.
        """
        decision = self.authorize(principal, source_id, name, context)
        if not decision.allowed:
            raise ToolConnectDenied(decision)
        return decision

    def redeem(self, grant_id: str, principal: Mapping[str, Any],
              args: Mapping[str, Any]) -> ClientRedemption:
        """Atomically consume a one-use grant immediately before executing the call.

        Resubmits the raw ``args`` — the server is the only hasher, so the client
        never learns or re-derives the canonicalization rule. Any transport failure,
        non-200, or a body missing ``"redeemed"`` raises :class:`ToolConnectUnavailable`
        rather than returning a redeemed result — there is no path back to the caller
        that looks like success without the server's explicit say-so.
        """
        body = {"principal": dict(principal), "args": dict(args)}
        status, payload = self._request("POST", f"/grants/{grant_id}/redeem", body)
        if status != 200 or not isinstance(payload, dict) or "redeemed" not in payload:
            raise ToolConnectUnavailable(
                f"/grants/{grant_id}/redeem returned {status}: {payload!r}")
        cv = str(payload.get("contract_version", ""))
        major = (cv or "0").split(".", 1)[0]
        if cv and major != self.EXPECTED_CONTRACT_MAJOR:
            # Same fail-closed discipline as authorize(): a future server on an
            # incompatible major could reuse the "redeemed" field name with different
            # semantics — never let that read as a genuine redemption at the one
            # boundary where getting it wrong executes a tool.
            raise ToolConnectUnavailable(
                f"redeem response contract v{cv} is incompatible with "
                f"client-expected major {self.EXPECTED_CONTRACT_MAJOR}")
        return ClientRedemption(
            redeemed=payload.get("redeemed") is True,
            reason=str(payload.get("reason", "")),
            grant_id=str(payload.get("grant_id", grant_id)),
            decision_id=str(payload.get("decision_id") or ""),
            source_id=str(payload.get("source_id") or ""),
            name=str(payload.get("name") or ""),
            contract_version=str(payload.get("contract_version", "")),
            raw=dict(payload),
        )

    def close_grant(self, grant_id: str, reason: str = "explicit_close") -> dict:
        """Explicitly close a grant (e.g. abandon-in-``finally``). Idempotent."""
        status, payload = self._request(
            "POST", f"/grants/{grant_id}/close", {"reason": reason})
        if status != 200 or not isinstance(payload, dict):
            raise ToolConnectUnavailable(
                f"closing grant {grant_id} returned {status}: {payload!r}")
        return payload

    def record_outcome(self, decision_id: str, outcome: str,
                       detail: Mapping[str, Any] | None = None,
                       grant_id: str | None = None) -> dict:
        """Close the loop on an issued decision (contract §3: ``record()``).

        ``grant_id``, when given, closes that grant in the same call (contract 1.1).
        """
        body: dict[str, Any] = {"outcome": outcome}
        if detail is not None:
            body["detail"] = dict(detail)
        if grant_id is not None:
            body["grant_id"] = grant_id
        status, payload = self._request(
            "POST", f"/decisions/{decision_id}/outcome", body)
        if status != 200 or not isinstance(payload, dict):
            raise ToolConnectUnavailable(
                f"recording outcome for {decision_id} returned {status}: {payload!r}")
        return payload

    # -- governed invocation ------------------------------------------------------

    def governed_invoke(self, principal: Mapping[str, Any], source_id: str, name: str,
                        args: Mapping[str, Any], executor: Callable[[Mapping[str, Any]], Any], *,
                        context: Mapping[str, Any] | None = None,
                        ttl_seconds: int | None = None) -> Any:
        """authorize(final args) -> redeem -> executor(frozen_args) -> outcome.

        This is the governed-invoke helper: ANY failure before execution refuses
        (raises) — fail-closed. ToolConnect never carries the request; ``executor`` is
        the caller's own invocation, called with the exact deep-copied mapping that was
        hashed and redeemed, so a caller mutating its own ``args`` after the call
        starts cannot desynchronize what was authorized from what runs.

        Raises :class:`ToolConnectDenied` on an authorize-deny, :class:`GrantRedeemDenied`
        on a redeem-deny, :class:`ToolConnectUnavailable` on a stale pre-1.1 server (an
        allow with no grant) or any transport failure. If ``executor`` raises, the
        original exception propagates; best-effort cleanup (close the grant, record an
        "error" outcome) is attempted first and never masks it. After a successful
        execution, outcome reporting is best-effort — an audit-path outage never
        destroys a result that already executed.
        """
        frozen = copy.deepcopy(dict(args))
        decision = self.authorize(principal, source_id, name, context=context,
                                  args=frozen, ttl_seconds=ttl_seconds)
        if not decision.allowed:
            raise ToolConnectDenied(decision)
        if decision.grant is None:
            # Mixed-fleet rule: allow-without-grant when args were sent is not a usable
            # allow — either a pre-1.1 server silently dropped `args`, or this build's
            # own invariant broke. Either way, refuse rather than execute ungoverned.
            raise ToolConnectUnavailable(
                "authorize allowed but issued no grant (server pre-1.1?)")
        grant = decision.grant
        try:
            redemption = self.redeem(grant.grant_id, principal, frozen)
            if not redemption.redeemed:
                raise GrantRedeemDenied(redemption)
            if (redemption.source_id and redemption.source_id != source_id) or (
                    redemption.name and redemption.name != name):
                raise ToolConnectUnavailable(
                    f"redeemed grant is for {redemption.source_id}:{redemption.name}, "
                    f"expected {source_id}:{name}")
            result = executor(frozen)
        except BaseException:
            try:
                self.close_grant(grant.grant_id, "aborted")
            except ToolConnectError:
                pass
            try:
                self.record_outcome(decision.decision_id, "error", grant_id=grant.grant_id)
            except ToolConnectError:
                pass
            raise
        try:
            self.record_outcome(decision.decision_id, "executed", grant_id=grant.grant_id)
        except ToolConnectError:
            pass  # post-execution audit outage never destroys the result
        return result
