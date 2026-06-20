#!/usr/bin/env python3
"""Import ClamAV's whole-file hash signatures into AetherAV's hash DB.

ClamAV CVD = 512-byte ASCII header + gzipped tar of signature files. We take
only the *whole-file* hash signatures so they match our full-file scan:

  *.hdb / *.hdu :  md5:size:name          (hash = field 0)
  *.hsb / *.hsu :  sha1|sha256:size:name  (hash = field 0)

We deliberately SKIP *.mdb/*.msb (PE *section* hashes - partial, never match a
whole-file digest) and the pattern signatures (*.ndb/*.ldb - need a pattern
engine, not hashes). AetherAV's engine matches md5/sha1/sha256, so all of these
are usable.

Usage:
  python3 tools/import_clamav.py                 # main.cvd + daily.cvd
  python3 tools/import_clamav.py --daily-only     # just daily (fast, ~55k)
"""
import gzip, io, sys, os, tarfile, urllib.request

ROOT = "/home/nexland/AetherAV"
DB = f"{ROOT}/assets/signatures/hashes.db"
MIRROR = "https://database.clamav.net"
UA = "ClamAV/1.3.0"  # the mirror rejects unknown user agents
HEX = set("0123456789abcdef")
WHOLE_FILE_EXT = (".hdb", ".hdu", ".hsb", ".hsu")


def fetch(name: str) -> bytes | None:
    url = f"{MIRROR}/{name}"
    print(f">> downloading {url}", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=300) as r:
            data = r.read()
        print(f"   {len(data)//1024//1024} MB", flush=True)
        return data
    except Exception as e:
        print(f"   FAILED: {e}", flush=True)
        return None


NDB_EXT = (".ndb", ".ndu")


def parse_cvd(cvd: bytes, ndb_out: list):
    """Yield (hash, name) from a CVD's whole-file hash signatures; append any
    `.ndb` body-signature lines to `ndb_out` for the pattern engine."""
    body = cvd[512:]  # strip the ASCII header
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.name.endswith(NDB_EXT):
                f = tf.extractfile(m)
                if f:
                    ndb_out.append(f.read().decode("utf-8", "ignore"))
                continue
            if not m.name.endswith(WHOLE_FILE_EXT):
                continue
            f = tf.extractfile(m)
            if not f:
                continue
            for line in f.read().decode("utf-8", "ignore").splitlines():
                parts = line.split(":")
                if len(parts) < 3:
                    continue
                h = parts[0].strip().lower()
                if len(h) in (32, 40, 64) and all(c in HEX for c in h):
                    name = parts[2].strip() or "ClamAV.Sample"
                    yield h, name


def main():
    daily_only = "--daily-only" in sys.argv
    sources = ["daily.cvd"] if daily_only else ["main.cvd", "daily.cvd"]

    sigs: dict[str, str] = {}
    ndb_chunks: list = []
    for src in sources:
        cvd = fetch(src)
        if not cvd:
            continue
        n = 0
        for h, name in parse_cvd(cvd, ndb_chunks):
            sigs[h] = name
            n += 1
        print(f">> {src}: {n} whole-file hash signatures", flush=True)

    # Write the ClamAV body-signature (.ndb) set for the pattern engine.
    if ndb_chunks:
        ndb_path = f"{ROOT}/assets/signatures/patterns.ndb"
        text = "\n".join(c.strip("\n") for c in ndb_chunks) + "\n"
        with open(ndb_path, "w") as f:
            f.write(text)
        print(f">> wrote {text.count(chr(10))} .ndb pattern lines to {ndb_path}", flush=True)

    if not sigs:
        print("!! nothing imported (mirror unreachable?)", flush=True)
        return 1

    # Merge into the existing DB (dedup, keep header).
    header = "# AetherAV hash signature database"
    existing: set[str] = set()
    if os.path.exists(DB):
        for l in open(DB):
            l = l.rstrip("\n")
            if l.startswith("#"):
                continue
            if l.strip():
                existing.add(l)
    before = len(existing)
    for h, name in sigs.items():
        existing.add(f"{h} ClamAV.{name}")
    added = len(existing) - before
    with open(DB, "w") as f:
        f.write(header + "\n")
        f.write("\n".join(sorted(existing)) + "\n")
    print(f">> merged: +{added} new ({len(sigs)} ClamAV hashes), "
          f"total DB = {len(existing)} signatures", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
