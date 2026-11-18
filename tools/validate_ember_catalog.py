#!/usr/bin/env python3
"""Validate EMBER2024 feature archives and build a review-only SHA-256 list."""

import argparse
import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

SHA256 = re.compile(r"[a-fA-F0-9]{64}")
EXCLUDED_DIGESTS = {bytes(32), hashlib.sha256(b"").digest()}
RATIO = re.compile(r"([0-9]{1,4})/([0-9]{1,4})")
MAX_ROW_BYTES = 1024 * 1024


def verified_archive(spec):
    expected, sep, name = spec.partition("=")
    if not sep or not SHA256.fullmatch(expected):
        raise ValueError("each archive must be EXPECTED_SHA256=PATH")
    path = Path(name)
    with path.open("rb") as handle:
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    if actual != expected.lower():
        raise ValueError(f"{path.name}: source checksum mismatch")
    return path, actual


def iter_observations(path, minimum):
    with ZipFile(path) as archive:
        members = [entry for entry in archive.infolist() if entry.filename.endswith(".jsonl")]
        if not members or len({entry.filename for entry in members}) != len(members):
            raise ValueError(f"{path.name}: missing or duplicate JSONL members")
        for member in members:
            with archive.open(member) as handle:
                line_number = 0
                while line := handle.readline(MAX_ROW_BYTES + 1):
                    line_number += 1
                    if len(line) > MAX_ROW_BYTES:
                        raise ValueError(f"{member.filename}:{line_number}: record too large")
                    row = json.loads(line)
                    digest, label = row.get("sha256"), row.get("label")
                    ratio = RATIO.fullmatch(str(row.get("detection_ratio")))
                    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                        raise ValueError(f"{member.filename}:{line_number}: invalid SHA-256")
                    if type(label) is not int or label not in (-1, 0, 1):
                        raise ValueError(f"{member.filename}:{line_number}: invalid label")
                    if not ratio:
                        raise ValueError(f"{member.filename}:{line_number}: invalid detection ratio")
                    detections, total = map(int, ratio.groups())
                    if not 0 < total or detections > total:
                        raise ValueError(f"{member.filename}:{line_number}: invalid detection count")
                    digest_bytes = bytes.fromhex(digest)
                    eligible = label == 1 and detections >= minimum
                    yield (
                        digest_bytes, int(label == 0), int(label == 1),
                        int(eligible and digest_bytes not in EXCLUDED_DIGESTS),
                    )


def stage(sources, output, minimum):
    files = [verified_archive(spec) for spec in sources]
    if len({digest for _, digest in files}) != len(files):
        raise ValueError("an archive was supplied more than once")
    with TemporaryDirectory(dir=output.parent) as temp:
        tmp = Path(temp)
        with closing(sqlite3.connect(tmp / "catalog.sqlite")) as db:
            db.execute(
                "CREATE TABLE samples (sha BLOB PRIMARY KEY, benign INT, malicious INT,"
                " candidate INT) WITHOUT ROWID"
            )
            source_stats = []
            for path, source_digest in files:
                count = 0

                def count_rows():
                    nonlocal count
                    for row in iter_observations(path, minimum):
                        count += 1
                        yield row

                with db:
                    db.executemany(
                        "INSERT INTO samples VALUES (?, ?, ?, ?) ON CONFLICT(sha) DO UPDATE SET"
                        " benign=max(benign,excluded.benign),"
                        " malicious=max(malicious,excluded.malicious),"
                        " candidate=max(candidate,excluded.candidate)",
                        count_rows(),
                    )
                source_stats.append({"name": path.name, "sha256": source_digest, "rows": count})
            total, conflicts, excluded, candidates = db.execute(
                "SELECT count(*), count(*) FILTER (WHERE benign AND malicious),"
                " count(*) FILTER (WHERE malicious AND NOT benign AND NOT candidate),"
                " count(*) FILTER (WHERE candidate AND NOT benign) FROM samples"
            ).fetchone()
            staged = tmp / "review.sha256"
            with staged.open("w", encoding="ascii") as out:
                for (digest,) in db.execute(
                    "SELECT sha FROM samples WHERE candidate AND NOT benign ORDER BY sha"
                ):
                    out.write(digest.hex() + "\n")
            with staged.open("rb") as inp:
                catalog_digest = hashlib.file_digest(inp, "sha256").hexdigest()
            # Publish only after a complete pass. Hard link creates the target
            # atomically and refuses to overwrite an existing review list.
            output.hardlink_to(staged)
    return {
        "sources": source_stats,
        "unique_records": total,
        "duplicate_observations": sum(source["rows"] for source in source_stats) - total,
        "conflicting_labels": conflicts,
        "excluded_malicious_label": excluded,
        "review_candidates": candidates,
        "minimum_detections": minimum,
        "catalog_sha256": catalog_digest,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", metavar="EXPECTED_SHA256=PATH")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--min-detections", type=int, default=10)
    args = parser.parse_args()
    if args.min_detections < 1:
        parser.error("--min-detections must be positive")
    try:
        report = stage(args.archives, args.out, args.min_detections)
    except (OSError, ValueError, sqlite3.Error, BadZipFile) as exc:
        parser.exit(1, f"catalog validation failed: {exc}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
