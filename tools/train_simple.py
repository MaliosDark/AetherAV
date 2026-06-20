#!/usr/bin/env python3
"""Dependency-free logistic-regression trainer for the static PE model.

A stdlib-only fallback to `train_pe_model.py` (which needs scikit-learn): trains
by batch gradient descent with z-score standardization and exports a model JSON
that `aether-ml` loads directly. Feed it a real labeled feature CSV for a
production model; with `--demo` it trains on a synthetic dataset so the pipeline
can be exercised end-to-end without any third-party packages.

CSV columns must match aether_ml::features::PE_FEATURES (see FEATURES below),
plus a `label` column (1 = malicious, 0 = benign).

Usage:
  python tools/train_simple.py --demo --out /tmp/pe_trained.json
  python tools/train_simple.py --data features.csv --out assets/models/pe.json
"""
from __future__ import annotations
import argparse, csv, json, math, random

FEATURES = [
    "section_count", "max_entropy", "mean_entropy", "has_wx", "import_count",
    "import_dll_count", "suspicious_import_count", "has_injection_combo",
    "is_dll", "high_entropy_ratio", "anonymous_section", "tiny_imports",
]


def synth(n, rng):
    """Synthetic rows reflecting documented benign/packed-malware distributions.
    (Synthetic - replace with a real feature corpus for production.)"""
    rows = []
    for _ in range(n):
        malicious = rng.random() < 0.5
        if malicious:  # packed / injecting sample
            f = [rng.gauss(5, 2), rng.gauss(7.6, 0.4), rng.gauss(7.0, 0.5),
                 1 if rng.random() < 0.6 else 0, rng.gauss(8, 6),
                 rng.gauss(2, 1), rng.gauss(3, 1.5), 1 if rng.random() < 0.5 else 0,
                 0, rng.uniform(0.4, 1.0), 1 if rng.random() < 0.4 else 0,
                 1 if rng.random() < 0.5 else 0]
        else:          # ordinary benign binary
            f = [rng.gauss(5, 1.5), rng.gauss(6.2, 0.5), rng.gauss(5.8, 0.5),
                 0, rng.gauss(90, 50), rng.gauss(6, 3), rng.gauss(0.3, 0.6),
                 0, 1 if rng.random() < 0.3 else 0, rng.uniform(0.0, 0.2),
                 0, 0]
        rows.append((f, 1 if malicious else 0))
    return rows


def load_csv(path):
    rows = []
    with open(path) as fh:
        for r in csv.DictReader(fh):
            rows.append(([float(r[c]) for c in FEATURES], int(float(r["label"]))))
    return rows


def standardize(rows):
    n, d = len(rows), len(FEATURES)
    mean = [sum(r[0][j] for r in rows) / n for j in range(d)]
    var = [sum((r[0][j] - mean[j]) ** 2 for r in rows) / n for j in range(d)]
    scale = [math.sqrt(v) or 1.0 for v in var]
    return mean, scale


def train(rows, epochs=400, lr=0.3):
    d = len(FEATURES)
    mean, scale = standardize(rows)
    X = [[(r[0][j] - mean[j]) / scale[j] for j in range(d)] for r in rows]
    y = [r[1] for r in rows]
    w = [0.0] * d
    b = 0.0
    n = len(rows)
    for _ in range(epochs):
        gw = [0.0] * d
        gb = 0.0
        for xi, yi in zip(X, y):
            z = b + sum(w[j] * xi[j] for j in range(d))
            p = 1.0 / (1.0 + math.exp(-z))
            err = p - yi
            for j in range(d):
                gw[j] += err * xi[j]
            gb += err
        for j in range(d):
            w[j] -= lr * gw[j] / n
        b -= lr * gb / n
    return {"version": 1, "kind": "logistic", "features": FEATURES,
            "mean": mean, "scale": scale, "weights": w, "bias": b, "threshold": 0.6}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--out", default="/tmp/pe_trained.json")
    args = ap.parse_args()

    if args.demo or not args.data:
        rng = random.Random(1337)
        rows = synth(4000, rng)
    else:
        rows = load_csv(args.data)

    model = train(rows)
    with open(args.out, "w") as fh:
        json.dump(model, fh, indent=2)
    # quick train-accuracy readout
    mean, scale, w, b = model["mean"], model["scale"], model["weights"], model["bias"]
    correct = 0
    for feats, label in rows:
        z = b + sum(w[j] * (feats[j] - mean[j]) / scale[j] for j in range(len(w)))
        correct += int((1.0 / (1.0 + math.exp(-z)) >= 0.6) == bool(label))
    print(f"trained on {len(rows)} rows -> {args.out}  (train acc {100*correct/len(rows):.1f}%)")


if __name__ == "__main__":
    main()
