"""Best-effort projection onto the shared Connect-ecosystem event bus.

This module NEVER makes ToolConnect's decisions. ToolConnect's own hash-chained
audit log (``store.py``'s ``audit`` table, verified by ``verify_chain()``) is and
stays the one AUTHORITY for every decision, grant, and outcome — a Policy
Decision Point that is never itself in the invocation data path. What this
module adds is a fire-and-forget PROJECTION of four of those already-decided
facts onto AgentConnect's shared, cross-product ``event_log`` (the SHARED BUS
WIRE CONTRACT, shipped in AgentConnect ``docs/EVENT_BUS.md`` §9), purely for
fleet-wide observability. A publish succeeding, failing, or never being
attempted at all changes nothing about what ToolConnect just decided or
recorded — the row already landed in ToolConnect's own authoritative audit
before this module is ever called.

Emit points (wired in ``service.py``), wire ``type`` exactly:

* ``ToolConnectService.authorize`` -> ``tool.authorized``. An allow carries NO
  ``outcome`` (null/absent = allow, per EVENT_BUS.md §4.2 — ``"allowed"`` is not
  a member of the closed outcome vocabulary); a deny is ``tool.authorized`` +
  ``outcome="denied"``, never a separate wire type.
* ``ToolConnectService.authorize``, additionally, iff a grant was issued (args
  bound + allowed) -> ``grant.issued``.
* ``ToolConnectService.redeem_grant``, iff the redemption succeeded ->
  ``grant.redeemed`` (a denied redemption emits nothing — ToolConnect's own
  ``grant_redeem_denied`` audit kind already covers that path, and the bus
  contract does not reserve a wire id for it).
* ``ToolConnectService.record_outcome`` -> ``tool.executed``.

Payload discipline (SHARED BUS WIRE CONTRACT, defense in depth on top of the
AgentConnect ingress's own fail-closed re-redaction, docs/EVENT_BUS.md §9.3):
every payload built in ``service.py`` carries only ids, hashes, decision
outcomes, and policy names — principal id, source_id, tool qualified_name,
decision_id, grant_id, ``args_hash`` (never the arguments it was hashed from),
``reason``, ``determining_policies``. Raw tool call arguments, prompts, model
output, and secrets never reach this module because ToolConnect's own decision
core never computes or stores them in the first place (ADR 0001: no
``invoke()``, no data path) — there is structurally nothing to redact out of
these payloads that was not already absent upstream.

Privacy tier note: ToolConnect's own ``Principal.privacy_tier``
(``local | trusted-cloud | rented``) is a COMPUTE-TRUST classification — which
infrastructure class is running the calling principal — not the same
vocabulary as the shared bus's ``PrivacyTier``
(``public | public_redacted | repo_sensitive | local_only | secret_sensitive``),
a CONTENT-sensitivity classification the AgentConnect store re-validates and
re-redacts every ingested ``payload`` against (docs/EVENT_BUS.md §9.3).
Forwarding ToolConnect's raw tier string verbatim would simply fail closed to
``secret_sensitive`` on every single event (an unparseable tier wipes the
whole ``payload`` to a marker), which would erase payloads that never carried
anything beyond ids/hashes/decisions in the first place. ``_bus_tier_for``
below is therefore a deliberate, documented, conservative translation from the
compute-trust axis to the content-sensitivity axis (most-trusted compute
context maps to the loosest content tier), not a claim that the two concepts
are the same thing.

Fire-and-forget discipline: ``ToolConnectService`` is used both embedded
in-process (the MCP gateway, tests) and behind ``server.py``'s single-threaded
``http.server`` — there is no background worker/queue in this codebase to hand
a publish off to without adding one. ``publish()`` is therefore an ordinary
bounded synchronous HTTP call with a SHORT timeout (default 2s, well under any
caller's own request timeout), wrapped so EVERY exception — transport fault,
timeout, non-2xx, a malformed response, anything — is caught and logged at
``WARNING``, never raised into the caller. The tradeoff this accepts: a slow
(but not fully dead) bus can still stall a decision/redeem/outcome call for up
to ``timeout`` seconds, rather than truly zero. Unconfigured (the default — no
``TOOLCONNECT_BUS_URL``/``TOOLCONNECT_BUS_TOKEN``) or a dead/erroring bus both
degrade to a silent no-op: ToolConnect's own behavior is byte-identical either
way, because nothing about the call's return value or side effects depends on
whether the publish happened.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
import uuid
from typing import Any, Mapping, Optional

logger = logging.getLogger(__name__)

__all__ = ["BusPublisher"]

#: This product's identity on the wire (SHARED BUS WIRE CONTRACT: `source_product`).
SOURCE_PRODUCT = "toolconnect"

#: See the module docstring's "Privacy tier note". Most-trusted ToolConnect compute
#: context -> loosest bus content tier; least-trusted -> tightest (but still short of
#: the fail-closed default, since these payloads never carry raw content to protect).
_PRINCIPAL_TIER_TO_BUS_TIER = {
    "local": "public",
    "trusted-cloud": "repo_sensitive",
    "rented": "local_only",
}

#: Fail-closed default for an unrecognized/missing principal tier — same posture the
#: AgentConnect ingress itself uses for a missing/unparseable `privacy_tier` (§9.3).
_UNKNOWN_PRINCIPAL_TIER_BUS_TIER = "secret_sensitive"

#: Used only where no principal (and therefore no tier) is available at all — e.g.
#: `record_outcome`, whose public signature carries a `decision_id`/`outcome`/`detail`
#: and no principal. `"public"` is deliberate, not a fail-open shortcut: every payload
#: this module ever builds is ids/hashes/decision-codes only (see module docstring),
#: so there is nothing content-shaped for a stricter tier to protect at this call site.
NO_PRINCIPAL_BUS_TIER = "public"


def bus_tier_for_principal(principal_tier: Optional[str]) -> str:
    """Map a ToolConnect `Principal.privacy_tier` onto a bus `PrivacyTier` string."""
    return _PRINCIPAL_TIER_TO_BUS_TIER.get(
        principal_tier or "", _UNKNOWN_PRINCIPAL_TIER_BUS_TIER)


#: The shared bus `outcome` field is a CLOSED vocabulary (EVENT_BUS.md §1:
#: `succeeded | failed | cancelled | denied | timed_out | unknown | null`) and is
#: an exact-match filter on the consumer side (§5). `record_outcome`'s caller-supplied
#: `outcome` string, by contrast, is free-form ToolConnect application text ("success",
#: "executed", …) that its own authoritative audit stores verbatim. Projecting it onto
#: the bus therefore requires mapping it onto the closed vocabulary; an unrecognized
#: string maps to `"unknown"` (a valid member) rather than polluting the field, so a
#: fleet consumer filtering `?outcome=succeeded` reliably sees ToolConnect executions.
_EXECUTION_OUTCOME_TO_BUS_OUTCOME = {
    "succeeded": "succeeded",
    "success": "succeeded",
    "successful": "succeeded",
    "executed": "succeeded",
    "ok": "succeeded",
    "complete": "succeeded",
    "completed": "succeeded",
    "done": "succeeded",
    "failed": "failed",
    "failure": "failed",
    "error": "failed",
    "errored": "failed",
    "cancelled": "cancelled",
    "canceled": "cancelled",
    "denied": "denied",
    "timed_out": "timed_out",
    "timedout": "timed_out",
    "timeout": "timed_out",
}

#: Fail-safe bucket for any caller string not recognized above — a valid vocabulary
#: member, never the raw free-form string.
_UNKNOWN_EXECUTION_OUTCOME_BUS_OUTCOME = "unknown"


def bus_outcome_for_execution(outcome: Optional[str]) -> str:
    """Map `record_outcome`'s free-form outcome string onto the closed bus vocabulary."""
    return _EXECUTION_OUTCOME_TO_BUS_OUTCOME.get(
        (outcome or "").strip().lower(), _UNKNOWN_EXECUTION_OUTCOME_BUS_OUTCOME)


class BusPublisher:
    """Fire-and-forget publisher onto the shared AgentConnect event bus.

    Disabled (every `publish()` call becomes a no-op that touches the network
    not at all) unless constructed with both a `url` and a `token` — the
    default, `from_env()` with neither `TOOLCONNECT_BUS_URL` nor
    `TOOLCONNECT_BUS_TOKEN` set. Never raises; see the module docstring's
    "Fire-and-forget discipline".
    """

    def __init__(self, url: Optional[str], token: Optional[str], *,
                 timeout: float = 2.0) -> None:
        self.url = url.rstrip("/") if url else None
        self.token = token or None
        self.timeout = timeout
        #: True iff both a URL and a token are configured. Checked up front so a
        #: disabled publisher costs callers nothing beyond this one attribute read —
        #: no string formatting, no dict-building, no import of urllib's error types.
        self.enabled = bool(self.url and self.token)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "BusPublisher":
        """Build from the environment (or an injected mapping, for tests).

        Recognized vars: `TOOLCONNECT_BUS_URL` (AgentConnect's base URL, e.g.
        `http://localhost:8790`), `TOOLCONNECT_BUS_TOKEN` (a publish token minted
        via `agentconnect tokens publish --source-product toolconnect`), and the
        optional `TOOLCONNECT_BUS_TIMEOUT` (seconds, default 2.0). Absent either
        of the first two, the returned publisher is disabled — the same posture
        every other optional adapter in this codebase takes (ADR-documented
        elsewhere): missing configuration degrades to off, never to a guess.
        """
        env = env if env is not None else os.environ
        timeout_raw = env.get("TOOLCONNECT_BUS_TIMEOUT")
        try:
            timeout = float(timeout_raw) if timeout_raw else 2.0
        except ValueError:
            timeout = 2.0
        return cls(env.get("TOOLCONNECT_BUS_URL"), env.get("TOOLCONNECT_BUS_TOKEN"),
                   timeout=timeout)

    def publish(self, type: str, *, outcome: Optional[str] = None,  # noqa: A002
                actor: str = "", task_id: Optional[str] = None,
                subtask_id: Optional[str] = None,
                privacy_tier: str = _UNKNOWN_PRINCIPAL_TIER_BUS_TIER,
                payload: Optional[Mapping[str, Any]] = None,
                event_id: Optional[str] = None) -> None:
        """Publish one event onto the bus. Never raises, never blocks the caller
        beyond this instance's bounded `timeout` (module docstring, "Fire-and-
        forget discipline"). A disabled publisher (the default) returns
        immediately without touching the network at all.
        """
        if not self.enabled:
            return
        body: dict[str, Any] = {
            "type": type,
            "source_product": SOURCE_PRODUCT,
            "event_id": event_id or f"toolconnect_{uuid.uuid4().hex}",
            "actor": actor,
            "privacy_tier": privacy_tier,
            "payload": dict(payload or {}),
        }
        if outcome is not None:
            body["outcome"] = outcome
        if task_id is not None:
            body["task_id"] = task_id
        if subtask_id is not None:
            body["subtask_id"] = subtask_id
        self._post(body)

    # -- transport ----------------------------------------------------------------

    def _post(self, body: Mapping[str, Any]) -> None:
        # Deliberately swallows EVERYTHING, not just the network-shaped exceptions
        # `urllib` documents (`URLError`/`HTTPError`) — a serialization bug, a
        # threading/interpreter-shutdown race, anything at all. The bus is a
        # projection, never authoritative (module docstring); no publish failure
        # may ever propagate into a decision/redeem/outcome caller.
        try:
            data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                f"{self.url}/events", data=data, method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {self.token}"})
            with urllib.request.urlopen(req, timeout=self.timeout):
                pass
        except Exception as exc:  # noqa: BLE001 — see comment above
            logger.warning(
                "toolconnect: event bus publish failed (type=%r): %s",
                body.get("type"), exc)
