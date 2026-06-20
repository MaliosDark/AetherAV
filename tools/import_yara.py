#!/usr/bin/env python3
"""OPTIONAL: import a third-party community YARA ruleset.

By design AetherAV ships ONLY our own authored rules (assets/rules/*.yar). This
tool is an explicit OPT-IN for users who also want extra community coverage. It
writes to assets/community-rules/, which is NOT loaded by default - you must
point `engines.yara_rules` at it (or merge files into assets/rules/) yourself,
after reviewing them.

Why it's opt-in: we don't want our default detection to depend on a third party
that could be compromised. YARA rules are data (not code), so the worst a
poisoned rule can do is cause false positives/negatives - not run code - but we
still don't take that on by default. Anything we ship officially is reviewed and
delivered through our Ed25519-SIGNED feed instead.

Default source: Neo23x0/signature-base (Detection Rule License 1.1 - free to
use, incl. commercially, with attribution). Override with --url <tar.gz>.

Usage:
  python3 tools/import_yara.py            # downloads into assets/community-rules/
  python3 tools/import_yara.py --url <tar.gz>
"""
import io
import os
import sys
import tarfile
import urllib.request

ROOT = "/home/nexland/AetherAV"
DEST = f"{ROOT}/assets/community-rules"
DEFAULT_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz"


def main():
    url = DEFAULT_URL
    if "--url" in sys.argv:
        url = sys.argv[sys.argv.index("--url") + 1]

    print(f">> downloading {url}", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AetherAV-rule-importer"})
        with urllib.request.urlopen(req, timeout=180) as r:
            blob = r.read()
    except Exception as e:
        print(f"!! download failed: {e}", flush=True)
        return 1
    print(f"   {len(blob)//1024} KB", flush=True)

    os.makedirs(DEST, exist_ok=True)
    written = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            low = m.name.lower()
            # Only YARA rule files, and skip index/aggregator files that just
            # `include` others (they break a flat extraction).
            if not (low.endswith(".yar") or low.endswith(".yara")):
                continue
            if os.path.basename(low).startswith(("index", "_index", "yara-rules_index")):
                continue
            data = tf.extractfile(m)
            if not data:
                continue
            content = data.read()
            if b"include " in content[:4096] and b"rule " not in content:
                continue  # pure include-aggregator
            flat = os.path.basename(m.name)
            with open(os.path.join(DEST, flat), "wb") as f:
                f.write(content)
            written += 1

    print(f">> wrote {written} THIRD-PARTY rule files to {DEST}", flush=True)
    print(">> these are NOT loaded by default. To use them (after reviewing):", flush=True)
    print(f">>   aether -c <cfg> scan ...   with engines.yara_rules = {DEST}", flush=True)
    print(">> or copy the ones you trust into assets/rules/.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
