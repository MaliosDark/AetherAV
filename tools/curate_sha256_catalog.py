#!/usr/bin/env python3
"""Stage corroborated SHA-256 signatures from operator-reviewed metadata sources."""

import argparse
import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

SHA256 = re.compile(rb"[a-fA-F0-9]{64}")
SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
EXCLUDED = {bytes(32), hashlib.sha256(b"").digest()}
LABELS = {b"malicious", b"benign", b"holdout"}


def source_spec(value):
    key, separator, filename = value.partition("=")
    source, colon, digest = key.partition(":")
    if not separator or not colon or not SOURCE_ID.fullmatch(source) or not re.fullmatch(
        r"[a-fA-F0-9]{64}", digest
    ):
        raise argparse.ArgumentTypeError("expected SOURCE_ID:SHA256=PATH")
    return source.lower(), digest.lower(), Path(filename)


def rows(data, name):
    while raw := data.readline(128):
        fields = raw.rstrip(b"\r\n").split(b"\t")
        if len(raw) >= 128 or len(fields) != 2 or not SHA256.fullmatch(fields[0]) or fields[1] not in LABELS:
            raise ValueError(f"{name}: expected a SHA-256 and a tab-separated malicious, benign or holdout label")
        digest, label = bytes.fromhex(fields[0].decode("ascii")), fields[1]
        yield digest, int(label == b"malicious"), int(label != b"malicious" or digest in EXCLUDED)


def stage(sources, output, minimum_sources, minimum_entries):
    with TemporaryDirectory(dir=output.parent) as tmp:
        path = Path(tmp)
        with closing(sqlite3.connect(path / "evidence.sqlite")) as db:
            db.executescript(
                "CREATE TABLE samples (digest BLOB PRIMARY KEY, votes INTEGER, veto INTEGER) WITHOUT ROWID;"
                "CREATE TABLE source (digest BLOB PRIMARY KEY, vote INTEGER, veto INTEGER) WITHOUT ROWID;"
            )
            for name, expected, source_path in sources:
                with source_path.open("rb") as source:
                    if hashlib.file_digest(source, "sha256").hexdigest() != expected:
                        raise ValueError(f"{name}: source checksum mismatch")
                    source.seek(0)
                    with db:
                        db.executemany(
                            "INSERT INTO source VALUES (?,?,?) ON CONFLICT(digest) DO UPDATE SET"
                            " vote=max(vote,excluded.vote), veto=max(veto,excluded.veto)",
                            rows(source, name),
                        )
                        db.execute(
                            "INSERT INTO samples SELECT digest,vote,veto FROM source WHERE true"
                            " ON CONFLICT(digest) DO UPDATE SET votes=votes+excluded.votes,"
                            " veto=max(samples.veto,excluded.veto)"
                        )
                        db.execute("DELETE FROM source")
            count = db.execute(
                "SELECT count(*) FROM samples WHERE votes>=? AND veto=0", (minimum_sources,)
            ).fetchone()[0]
            if count < minimum_entries:
                raise ValueError(f"{count} eligible unique signatures; {minimum_entries} required")
            staged = path / "reviewed.sha256"
            with staged.open("wb") as handle:
                for (digest,) in db.execute(
                    "SELECT digest FROM samples WHERE votes>=? AND veto=0 ORDER BY digest",
                    (minimum_sources,),
                ):
                    handle.write(digest.hex().encode("ascii") + b"\n")
            with staged.open("rb") as handle:
                sha256 = hashlib.file_digest(handle, "sha256").hexdigest()
            output.hardlink_to(staged)
    return {
        "unique_sha256": count,
        "minimum_sources": minimum_sources,
        "input_sources": [{"id": name, "sha256": digest} for name, digest, _ in sources],
        "catalog_sha256": sha256,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", metavar="SOURCE_ID:SHA256=PATH", nargs="+", type=source_spec)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--min-sources", type=int, default=2)
    parser.add_argument("--min-entries", type=int, default=1)
    args = parser.parse_args()
    if not 2 <= args.min_sources <= len(args.sources) or args.min_entries < 1:
        parser.error("require at least two sources and one unique entry")
    if len({name for name, _, _ in args.sources}) != len(args.sources):
        parser.error("source IDs must be distinct")
    if len({digest for _, digest, _ in args.sources}) != len(args.sources):
        parser.error("identical source content cannot count as corroboration")
    try:
        print(json.dumps(stage(args.sources, args.out, args.min_sources, args.min_entries), indent=2))
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"catalog curation failed: {exc}\n")


if __name__ == "__main__":
    main()
