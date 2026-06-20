#!/usr/bin/env python3
"""Train the static PE classifier and export it for the Rust engine.

This is the Python side of AetherAV's ML pipeline. It trains a model on a
labeled corpus of PE feature vectors and emits a JSON file that
`aether-ml` loads at runtime (`assets/models/pe.json`).

Two export paths:
  * --kind logistic : exports standardized logistic-regression params as the
    pure-Rust model consumes (no native deps in the engine).
  * --kind onnx     : exports a LightGBM/XGBoost model to ONNX for the engine's
    optional `onnx` backend (heavier, higher accuracy).

The FEATURES list below is the contract with Rust: it must match
`aether_ml::features::PE_FEATURES` exactly, in order.

Usage:
    python tools/train_pe_model.py --data features.csv --label-col label \
        --kind logistic --out assets/models/pe.json

Expected CSV: one row per sample, the feature columns named below plus a
binary label column (1 = malicious, 0 = benign).
"""
from __future__ import annotations

import argparse
import json
import sys

FEATURES = [
    "section_count",
    "max_entropy",
    "mean_entropy",
    "has_wx",
    "import_count",
    "import_dll_count",
    "suspicious_import_count",
    "has_injection_combo",
    "is_dll",
    "high_entropy_ratio",
    "anonymous_section",
    "tiny_imports",
]


def train_logistic(X, y):
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler().fit(X)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(scaler.transform(X), y)

    return {
        "version": 1,
        "kind": "logistic",
        "features": FEATURES,
        "mean": scaler.mean_.astype(float).tolist(),
        "scale": scaler.scale_.astype(float).tolist(),
        "weights": clf.coef_[0].astype(float).tolist(),
        "bias": float(clf.intercept_[0]),
        "threshold": 0.6,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True, help="CSV of feature vectors + label")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--kind", choices=["logistic", "onnx"], default="logistic")
    ap.add_argument("--out", default="assets/models/pe.json")
    args = ap.parse_args()

    import pandas as pd  # imported lazily so --help works without deps

    df = pd.read_csv(args.data)
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        sys.exit(f"missing feature columns: {missing}")

    X = df[FEATURES].to_numpy(dtype="float32")
    y = df[args.label_col].to_numpy()

    if args.kind == "logistic":
        model = train_logistic(X, y)
        with open(args.out, "w") as f:
            json.dump(model, f, indent=2)
        print(f"wrote logistic model -> {args.out}")
    else:
        # ONNX path: train LightGBM, convert with onnxmltools/skl2onnx, and save
        # alongside a tiny JSON manifest the engine reads to find the .onnx file.
        sys.exit("onnx export: install lightgbm + onnxmltools and extend this stub")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
