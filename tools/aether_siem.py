#!/usr/bin/env python3
"""Persist AetherAV security events and query the local SIEM journal."""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

SCHEMA = "aether.security_event.v1"
MAX_LINE = 64 * 1024
MAX_ROWS = 250_000
MAX_BATCH_BYTES = 128 * 1024 * 1024


def event_rows(stream, received_at):
    number = 0
    total_bytes = 0
    while raw := stream.readline(MAX_LINE + 1):
        number += 1
        total_bytes += len(raw)
        if len(raw) > MAX_LINE or number > MAX_ROWS or total_bytes > MAX_BATCH_BYTES:
            raise ValueError("input exceeds SIEM batch limits")
        event = json.loads(raw)
        if not isinstance(event, dict) or event.get("schema") != SCHEMA:
            raise ValueError(f"line {number}: unsupported event schema")
        ts = event.get("event_time_us")
        if type(ts) is not int or not 0 < ts <= 9_223_372_036_854_775_807:
            raise ValueError(f"line {number}: invalid event time")
        fields = [event.get(key) for key in ("host", "rule_id", "severity")]
        if any(not isinstance(value, str) or not 0 < len(value) <= 253
               or any(ord(ch) < 32 for ch in value) for value in fields):
            raise ValueError(f"line {number}: missing or invalid host, rule or severity")
        expected = event.get("event_id")
        if expected is not None and (
            not isinstance(expected, str) or len(expected) != 64
            or any(ch not in "0123456789abcdef" for ch in expected)
        ):
            raise ValueError(f"line {number}: invalid event ID")
        body = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = expected or hashlib.sha256(body.encode()).hexdigest()
        yield digest, ts, received_at, *fields, body


def run(db, args):
    db.execute("""CREATE TABLE IF NOT EXISTS security_event (
        id TEXT PRIMARY KEY, ts INTEGER NOT NULL, received INTEGER NOT NULL,
        host TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL, json TEXT NOT NULL
        ) WITHOUT ROWID""")
    db.execute("CREATE INDEX IF NOT EXISTS event_ts ON security_event(ts)")
    db.execute("CREATE INDEX IF NOT EXISTS event_received ON security_event(received)")
    if args.command == "ingest":
        with db:
            inserted = db.executemany(
                "INSERT INTO security_event VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
                event_rows(sys.stdin.buffer, int(time.time())),
            ).rowcount
        print(json.dumps({"inserted": inserted}))
    elif args.command == "prune":
        cutoff = int(time.time()) - args.days * 86_400
        with db:
            removed = db.execute("DELETE FROM security_event WHERE received < ?", (cutoff,)).rowcount
        print(json.dumps({"removed": removed}))
    elif args.command == "summary":
        for host, severity, count in db.execute(
            "SELECT host,severity,count(*) FROM security_event GROUP BY host,severity ORDER BY host,severity"
        ):
            print(json.dumps({"host": host, "severity": severity, "count": count}))
    else:
        for (event,) in db.execute(
            """SELECT json FROM security_event
            WHERE (? IS NULL OR host=?) AND (? IS NULL OR severity=?)
            ORDER BY ts DESC, id LIMIT ?""",
            (args.host, args.host, args.severity, args.severity, args.limit),
        ):
            print(event)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ingest")
    commands.add_parser("summary")
    query = commands.add_parser("query")
    query.add_argument("--host")
    query.add_argument("--severity")
    query.add_argument("--limit", type=int, default=100)
    prune = commands.add_parser("prune")
    prune.add_argument("--days", type=int, required=True)
    args = parser.parse_args()
    if args.command == "query" and not 1 <= args.limit <= 10_000:
        parser.error("--limit must be between 1 and 10000")
    if args.command == "prune" and not 1 <= args.days <= 3650:
        parser.error("--days must be between 1 and 3650")
    try:
        os.umask(0o077)
        with closing(sqlite3.connect(args.db, timeout=10)) as db:
            run(db, args)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"SIEM journal error: {exc}\n")


if __name__ == "__main__":
    main()
