"""The `toolconnect` command line: init-db, serve, version.

Configuration precedence: explicit flags > --config TOML file > defaults. The config
format is documented in docs/SERVICE.md with a worked example in
examples/toolconnect.toml.

`serve` refuses to start without a Cedar policy file. A decision point with no
policies would default-deny everything, which is safe but almost certainly a
misconfiguration; requiring the flag makes the operator say what they meant.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
from pathlib import Path


def _load_config(path: str | None) -> dict:
    if path is None:
        return {}
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"config file not found: {path}")
    with p.open("rb") as fh:
        data = tomllib.load(fh)
    if not isinstance(data, dict):
        raise SystemExit(f"config file {path} must be a TOML table")
    return data


def _cmd_version(_args) -> int:
    from . import __version__
    print(f"toolconnect {__version__}")
    return 0


def _cmd_init_db(args) -> int:
    from .store import SqliteStore
    cfg = _load_config(args.config)
    db = args.db or cfg.get("db")
    if not db:
        raise SystemExit("init-db requires --db PATH (or `db` in --config)")
    db = str(Path(db).expanduser())
    store = SqliteStore(db)
    chain = store.verify_chain()
    store.close()
    print(f"initialized {db} (schema v1, audit chain ok={chain.ok}, "
          f"records={chain.records})")
    return 0


def _cmd_serve(args) -> int:
    from .policy import CedarPolicyEngine
    from .server import DEFAULT_HOST, DEFAULT_PORT, serve
    from .service import ToolConnectService
    from .store import SqliteStore

    cfg = _load_config(args.config)
    db = args.db or cfg.get("db")
    policies_path = args.policies or cfg.get("policies")
    host = args.host or cfg.get("host") or DEFAULT_HOST
    port = args.port if args.port is not None else int(cfg.get("port", DEFAULT_PORT))

    # Auth token: never from a bare flag by default (argv is visible in `ps`). Precedence
    # is env var > config file. `--token-env NAME` lets an operator name the variable.
    token_env = args.token_env or cfg.get("token_env") or "TOOLCONNECT_AUTH_TOKEN"
    token = os.environ.get(token_env) or cfg.get("token") or None
    rate_limit = (args.rate_limit if args.rate_limit is not None
                  else int(cfg.get("rate_limit_per_min", 0)))

    if not db:
        raise SystemExit("serve requires --db PATH (or `db` in --config)")
    if not policies_path:
        raise SystemExit(
            "serve requires --policies FILE (or `policies` in --config); "
            "a decision point must be told its policy set explicitly")
    if host not in ("127.0.0.1", "::1", "localhost") and not token:
        # A non-loopback bind with no token would put a fail-closed decision point on a
        # reachable interface with an open surface. Refuse; make the operator choose.
        raise SystemExit(
            f"refusing to bind {host} without authentication: set a token via "
            f"${token_env} (or `token` in --config), or bind 127.0.0.1. See "
            f"docs/SERVICE.md → Non-local deployment.")
    db = str(Path(db).expanduser())
    policies = Path(policies_path).expanduser()
    if not policies.exists():
        raise SystemExit(f"policy file not found: {policies_path}")

    try:
        engine = CedarPolicyEngine(policies.read_text())
    except ValueError as exc:
        # An unparseable policy set must never become a running server; refuse
        # with one actionable line instead of a traceback.
        raise SystemExit(f"{exc} (policy file: {policies_path})")
    store = SqliteStore(db)
    service = ToolConnectService(store, engine)
    auth_state = f"bearer (${token_env})" if token else "open (loopback)"
    rl_state = f"{rate_limit}/min/ip" if rate_limit > 0 else "off"
    print(f"toolconnect serving on http://{host}:{port} "
          f"(db={db}, policies={policies_path}, auth={auth_state}, "
          f"rate_limit={rl_state})", flush=True)
    try:
        serve(service, host=host, port=port, token=token,
              rate_limit_per_min=rate_limit)
    except KeyboardInterrupt:
        pass
    finally:
        store.close()
    return 0


def _cmd_verify_audit(args) -> int:
    """Walk the audit hash chain and report. Exit non-zero if it is broken — this is
    the shape an operator's cron job or health check wants."""
    from .store import SqliteStore
    cfg = _load_config(args.config)
    db = args.db or cfg.get("db")
    if not db:
        raise SystemExit("verify-audit requires --db PATH (or `db` in --config)")
    store = SqliteStore(str(Path(db).expanduser()))
    result = store.verify_chain().as_dict()
    store.close()
    if args.json:
        print(json.dumps(result))
    elif result["ok"]:
        print(f"audit chain OK ({result['records']} records)")
    else:
        print(f"audit chain BROKEN at seq {result['broken_at']}: {result['detail']} "
              f"({result['records']} records verified before the break)")
    return 0 if result["ok"] else 1


def _cmd_drift(args) -> int:
    """Report drift for a source against its last successful discovery. Exit non-zero
    when drift exists, so an operator can gate on it. Reuses the exact catalog logic
    the HTTP `/drift` route serves — no policy engine required."""
    from .store import SqliteStore
    cfg = _load_config(args.config)
    db = args.db or cfg.get("db")
    if not db:
        raise SystemExit("drift requires --db PATH (or `db` in --config)")
    store = SqliteStore(str(Path(db).expanduser()))
    try:
        cat = store.load_catalog()
        if args.source not in cat.sources:
            raise SystemExit(f"unknown source {args.source!r}")
        obs = store.last_discovery(args.source)
        if obs is None:
            raise SystemExit(
                f"no discovery has been observed for {args.source!r}; "
                f"trigger ingest first (drift is unknown, not clean)")
        discovered, observed_at = obs
        report = cat.drift(args.source, discovered)
    finally:
        store.close()
    payload = {
        "source_id": report.source_id,
        "clean": report.clean,
        "summary": report.summary(),
        "observed_at": observed_at,
        "advertised_missing": list(report.advertised_missing),
        "undeclared_present": list(report.undeclared_present),
        "unasserted": list(report.unasserted),
        "claim_conflicts": [list(c) for c in report.claim_conflicts],
        "redefined_after_assertion": list(report.redefined_after_assertion),
    }
    if args.json:
        print(json.dumps(payload))
    else:
        print(report.summary() + f"  (observed {observed_at})")
        for label, key in (("advertised-missing", "advertised_missing"),
                           ("undeclared-present", "undeclared_present"),
                           ("unasserted", "unasserted"),
                           ("redefined-after-assertion", "redefined_after_assertion")):
            if payload[key]:
                print(f"  {label}: {', '.join(payload[key])}")
        for name, msg in report.claim_conflicts:
            print(f"  claim-conflict {name}: {msg}")
    return 0 if report.clean else 2


def _cmd_backup(args) -> int:
    """Write a consistent snapshot of the database (schema + catalog + audit chain).
    Safe to run against a live service; SQLite's online backup is transactional."""
    from .store import SqliteStore
    cfg = _load_config(args.config)
    db = args.db or cfg.get("db")
    if not db:
        raise SystemExit("backup requires --db PATH (or `db` in --config)")
    if not args.out:
        raise SystemExit("backup requires --out PATH")
    store = SqliteStore(str(Path(db).expanduser()))
    dest = store.backup(str(Path(args.out).expanduser()))
    store.close()
    # Re-open the copy and verify its chain, so backup never silently produces a
    # corrupt artifact.
    verify = SqliteStore(dest)
    chain = verify.verify_chain()
    verify.close()
    print(f"backed up {db} -> {dest} (audit chain ok={chain.ok}, "
          f"records={chain.records})")
    return 0 if chain.ok else 1


def _cmd_audit(args) -> int:
    """Print recent audit records, newest first. Operator visibility into the chain."""
    from .store import SqliteStore
    cfg = _load_config(args.config)
    db = args.db or cfg.get("db")
    if not db:
        raise SystemExit("audit requires --db PATH (or `db` in --config)")
    store = SqliteStore(str(Path(db).expanduser()))
    records = store.read_audit(kind=args.kind, limit=args.limit)
    store.close()
    print(json.dumps(records, indent=2) if args.json
          else "\n".join(f"[{r['seq']}] {r['kind']}: {json.dumps(r['body'])}"
                          for r in records))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="toolconnect",
        description="Tool governance decision point. Authorizes and records; "
                    "never invokes.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_version = sub.add_parser("version", help="print the version")
    p_version.set_defaults(func=_cmd_version)

    p_init = sub.add_parser("init-db", help="create or open a database, verify its audit chain")
    p_init.add_argument("--db", help="path to the SQLite database")
    p_init.add_argument("--config", help="TOML config file")
    p_init.set_defaults(func=_cmd_init_db)

    p_serve = sub.add_parser("serve", help="run the HTTP decision service")
    p_serve.add_argument("--db", help="path to the SQLite database")
    p_serve.add_argument("--policies", help="path to a Cedar policy file")
    p_serve.add_argument("--host", help="bind host (default 127.0.0.1)")
    p_serve.add_argument("--port", type=int, help="bind port (default 8095)")
    p_serve.add_argument("--token-env", dest="token_env",
                         help="env var holding the bearer token "
                              "(default TOOLCONNECT_AUTH_TOKEN); required to bind a "
                              "non-loopback host")
    p_serve.add_argument("--rate-limit", dest="rate_limit", type=int,
                         help="requests per minute per client IP (0 = off)")
    p_serve.add_argument("--config", help="TOML config file")
    p_serve.set_defaults(func=_cmd_serve)

    p_verify = sub.add_parser("verify-audit",
                              help="walk the audit hash chain; exit 1 if broken")
    p_verify.add_argument("--db", help="path to the SQLite database")
    p_verify.add_argument("--config", help="TOML config file")
    p_verify.add_argument("--json", action="store_true", help="emit JSON")
    p_verify.set_defaults(func=_cmd_verify_audit)

    p_drift = sub.add_parser("drift",
                             help="report drift for a source; exit 2 if drift exists")
    p_drift.add_argument("--db", help="path to the SQLite database")
    p_drift.add_argument("--source", required=True, help="source_id to check")
    p_drift.add_argument("--config", help="TOML config file")
    p_drift.add_argument("--json", action="store_true", help="emit JSON")
    p_drift.set_defaults(func=_cmd_drift)

    p_backup = sub.add_parser("backup",
                              help="write a consistent snapshot of the database")
    p_backup.add_argument("--db", help="path to the SQLite database")
    p_backup.add_argument("--out", help="destination path for the snapshot")
    p_backup.add_argument("--config", help="TOML config file")
    p_backup.set_defaults(func=_cmd_backup)

    p_audit = sub.add_parser("audit", help="print recent audit records, newest first")
    p_audit.add_argument("--db", help="path to the SQLite database")
    p_audit.add_argument("--kind", help="filter by record kind")
    p_audit.add_argument("--limit", type=int, default=50, help="max records (default 50)")
    p_audit.add_argument("--config", help="TOML config file")
    p_audit.add_argument("--json", action="store_true", help="emit JSON")
    p_audit.set_defaults(func=_cmd_audit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
