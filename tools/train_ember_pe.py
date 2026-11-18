#!/usr/bin/env python3
"""Fit and evaluate an experimental AetherAV PE model on EMBER2024 metadata."""

import argparse
import json
from pathlib import Path
from zipfile import ZipFile

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from train_pe_model import FEATURES, train_logistic
from validate_ember_catalog import MAX_ROW_BYTES, verified_archive


def structural_features(row):
    """Use only fields with counterparts in the Rust PE extractor.

    Imports are omitted: pefile and goblin enumerate ordinals and duplicate
    libraries differently. Metadata cannot establish byte-level parser parity.
    """
    sections = row["section"]["sections"]
    entropy = [section["entropy"] for section in sections]
    return [
        len(sections),
        max(entropy, default=0),
        sum(entropy) / max(1, len(sections)),
        any({"MEM_EXECUTE", "MEM_WRITE"} <= set(s["props"]) for s in sections),
        0,
        0,
        0,
        0,
        "DLL" in row["header"]["coff"]["characteristics"],
        sum(value >= 6.8 for value in entropy) / max(1, len(sections)),
        any(not section["name"] for section in sections),
        0,
    ]


def load(path, file_type, weeks):
    records = {}
    conflicting = set()
    unlabelled = incompatible = duplicates = 0
    with ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.endswith(".jsonl"):
                continue
            with archive.open(name) as handle:
                while raw := handle.readline(MAX_ROW_BYTES + 1):
                    if len(raw) > MAX_ROW_BYTES:
                        raise ValueError(f"oversized record in {name}")
                    row = json.loads(raw)
                    if row["file_type"] != file_type or row["week_id"] not in weeks:
                        raise ValueError(f"unexpected file type or time window in {name}")
                    label = row["label"]
                    if label not in (0, 1):
                        unlabelled += 1
                        continue
                    if not row.get("section") or not row.get("header"):
                        incompatible += 1
                        continue
                    key = bytes.fromhex(row["sha256"])
                    if len(key) != 32:
                        raise ValueError(f"invalid SHA-256 in {name}")
                    record = (row["week_id"], label, structural_features(row))
                    if key in conflicting:
                        continue
                    if key in records:
                        duplicates += 1
                        if records[key][1:] != record[1:]:
                            del records[key]
                            conflicting.add(key)
                        elif record[0] < records[key][0]:
                            records[key] = record
                        continue
                    records[key] = record
    return records, conflicting, {
        "unlabelled": unlabelled, "incompatible": incompatible,
        "duplicates": duplicates, "conflicting_digests": len(conflicting),
    }


def arrays(records):
    _, labels, features = zip(*records, strict=True)
    x = np.asarray(features, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int8)
    if not np.isfinite(x).all() or len(np.unique(y)) != 2:
        raise ValueError("each time window must have finite features and both classes")
    return x, y


def scores(model, x):
    if model["features"] != FEATURES:
        raise ValueError("unexpected model feature schema")
    logits = (x - model["mean"]) / model["scale"] @ model["weights"] + model["bias"]
    return 1 / (1 + np.exp(-np.clip(logits, -80, 80)))


def metrics(y, predicted, threshold):
    tp = int(np.sum((predicted >= threshold) & (y == 1)))
    fp = int(np.sum((predicted >= threshold) & (y == 0)))
    positives = int(np.sum(y == 1))
    negatives = len(y) - positives
    return {
        "threshold": threshold, "tp": tp, "fp": fp,
        "tn": negatives - fp, "fn": positives - tp,
        "recall": tp / positives, "false_positive_rate": fp / negatives,
        "roc_auc": roc_auc_score(y, predicted),
        "average_precision": average_precision_score(y, predicted),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--train", required=True, metavar="SHA256=ZIP")
    p.add_argument("--test", required=True, metavar="SHA256=ZIP")
    p.add_argument("--type", default="Dot_Net", choices=["Dot_Net", "Win32", "Win64"])
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    train_path, train_sha = verified_archive(args.train)
    test_path, test_sha = verified_archive(args.test)
    train, train_conflicts, train_stats = load(train_path, args.type, range(52))
    test, test_conflicts, test_stats = load(test_path, args.type, range(52, 64))
    seen_train = train.keys() | train_conflicts
    overlap = len(seen_train & (test.keys() | test_conflicts))
    x_train, y_train = arrays(r for r in train.values() if r[0] < 44)
    x_cal, y_cal = arrays(r for r in train.values() if r[0] >= 44)
    x_test, y_test = arrays(r for k, r in test.items() if k not in seen_train)

    model = train_logistic(x_train, y_train)
    cal_scores = scores(model, x_cal)[y_cal == 0]
    # Tie scores stay below the threshold. Float32 matches the Rust threshold.
    percentile = np.quantile(cal_scores, 0.999, method="higher")
    model["threshold"] = float(np.nextafter(np.float32(percentile), np.float32(1)))
    fit = scores(model, x_test)
    baseline = json.loads(args.baseline.read_text())
    report = {
        "file_type": args.type, "train_archive_sha256": train_sha, "test_archive_sha256": test_sha,
        "train_stats": train_stats, "test_stats": test_stats, "excluded_test_overlap": overlap,
        "train_rows": len(y_train), "calibration_rows": len(y_cal), "test_rows": len(y_test),
        "test_candidate": metrics(y_test, fit, model["threshold"]),
        "test_baseline_projected_features": metrics(y_test, scores(baseline, x_test), baseline["threshold"]),
    }
    with args.out.open("x", encoding="utf-8") as output:
        json.dump(model, output, indent=2)
        output.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
