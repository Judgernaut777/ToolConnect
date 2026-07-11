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

    if not db:
        raise SystemExit("serve requires --db PATH (or `db` in --config)")
    if not policies_path:
        raise SystemExit(
            "serve requires --policies FILE (or `policies` in --config); "
            "a decision point must be told its policy set explicitly")
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
    print(f"toolconnect serving on http://{host}:{port} "
          f"(db={db}, policies={policies_path})", flush=True)
    try:
        serve(service, host=host, port=port)
    except KeyboardInterrupt:
        pass
    finally:
        store.close()
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
    p_serve.add_argument("--config", help="TOML config file")
    p_serve.set_defaults(func=_cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
