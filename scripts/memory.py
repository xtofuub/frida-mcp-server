#!/usr/bin/env python3
"""Hunt-memory helper for the frida-mcp-server autonomous orchestration layer.

A tiny append-and-query store over JSONL files. The orchestration commands
(/autopilot, /hunt, /validate, /pickup) call this to persist findings,
winning techniques, and session journals so knowledge compounds across
targets and resumes across sessions.

Files (under <repo>/memory/, override with FRIDA_MEMORY_DIR):
  audit.jsonl    - validated findings + impact (one per line)
  patterns.jsonl - techniques that produced a finding, for cross-target reuse
  journal.jsonl  - session events + untested attack surface, for /pickup

Every record is target-scoped via a "bundle_id" field, so a single store
serves many apps without being fixed to any one of them.

Usage:
  memory.py log    <store> --bundle <id> --json '{"k": "v"}'
  memory.py query  <store> [--bundle <id>] [--grep TEXT] [--limit N]
  memory.py resume --bundle <id>          # what /pickup reads
  memory.py stats

  <store> = audit | patterns | journal
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

STORES = ("audit", "patterns", "journal")
ROTATE_BYTES = 10 * 1024 * 1024  # 10 MB
KEEP_BACKUPS = 3


def memory_dir() -> Path:
    env = os.environ.get("FRIDA_MEMORY_DIR")
    base = Path(env) if env else Path(__file__).resolve().parent.parent / "memory"
    base.mkdir(parents=True, exist_ok=True)
    return base


def store_path(store: str) -> Path:
    if store not in STORES:
        sys.exit(f"unknown store {store!r}; choose from {', '.join(STORES)}")
    return memory_dir() / f"{store}.jsonl"


def rotate_if_needed(path: Path) -> None:
    if not path.exists() or path.stat().st_size < ROTATE_BYTES:
        return
    for i in range(KEEP_BACKUPS, 0, -1):
        older = path.with_suffix(f".jsonl.{i}")
        newer = path.with_suffix(f".jsonl.{i - 1}") if i > 1 else path
        if newer.exists():
            if older.exists():
                older.unlink()
            newer.rename(older)


def read_records(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def cmd_log(args) -> None:
    path = store_path(args.store)
    rotate_if_needed(path)
    try:
        payload = json.loads(args.json)
    except json.JSONDecodeError as exc:
        sys.exit(f"--json is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        sys.exit("--json must be a JSON object")
    payload.setdefault("bundle_id", args.bundle)
    payload.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
    print(json.dumps({"ok": True, "store": args.store, "wrote": payload}))


def cmd_query(args) -> None:
    rows = list(read_records(store_path(args.store)))
    if args.bundle:
        rows = [r for r in rows if r.get("bundle_id") == args.bundle]
    if args.grep:
        needle = args.grep.lower()
        rows = [r for r in rows if needle in json.dumps(r, ensure_ascii=False).lower()]
    if args.limit:
        rows = rows[-args.limit:]
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def cmd_resume(args) -> None:
    """What /pickup reads: prior findings, winning patterns, untested surface."""
    out = {"bundle_id": args.bundle, "audit": [], "patterns": [], "untested": []}
    for r in read_records(store_path("audit")):
        if r.get("bundle_id") == args.bundle:
            out["audit"].append(r)
    for r in read_records(store_path("patterns")):
        # patterns are cross-target: surface ones for this app AND generic wins
        out["patterns"].append(r)
    for r in read_records(store_path("journal")):
        if r.get("bundle_id") == args.bundle and r.get("untested"):
            out["untested"].extend(r["untested"])
    print(json.dumps(out, indent=2, ensure_ascii=False))


def cmd_stats(_args) -> None:
    out = {}
    for store in STORES:
        path = store_path(store)
        n = sum(1 for _ in read_records(path))
        size = path.stat().st_size if path.exists() else 0
        out[store] = {"records": n, "bytes": size}
    print(json.dumps(out, indent=2))


def main() -> None:
    p = argparse.ArgumentParser(description="frida-mcp-server hunt-memory helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    lg = sub.add_parser("log", help="append a record")
    lg.add_argument("store", choices=STORES)
    lg.add_argument("--bundle", required=True)
    lg.add_argument("--json", required=True, help="JSON object to store")
    lg.set_defaults(func=cmd_log)

    q = sub.add_parser("query", help="read records")
    q.add_argument("store", choices=STORES)
    q.add_argument("--bundle")
    q.add_argument("--grep")
    q.add_argument("--limit", type=int)
    q.set_defaults(func=cmd_query)

    r = sub.add_parser("resume", help="prior state for a target (used by /pickup)")
    r.add_argument("--bundle", required=True)
    r.set_defaults(func=cmd_resume)

    s = sub.add_parser("stats", help="record counts per store")
    s.set_defaults(func=cmd_stats)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
