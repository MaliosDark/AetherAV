#!/usr/bin/env python3
"""Load malware TLSH digests from MalwareBazaar's full export into the engine's
TLSH variant database - NO samples needed (the export lists a `tlsh` per sample),
so we get millions of variant fingerprints for free.

  ABUSE_CH_AUTH_KEY=<key> python3 tools/import_tlsh.py        # download + import
  python3 tools/import_tlsh.py path/to/full.csv               # parse a local CSV
  python3 tools/import_tlsh.py --selftest                     # verify the parser

abuse.ch needs a free Auth-Key now: https://auth.abuse.ch/
Output: assets/signatures/tlsh.db  (lines: "<TLSH>  <family>")  -- the engine
loads this when engines.tlsh is on.
"""
import csv, io, os, sys, urllib.request, zipfile

OUT = os.environ.get("AETHER_TLSH_DB", "assets/signatures/tlsh.db")
URL = "https://bazaar.abuse.ch/export/csv/full/"
# MalwareBazaar full.csv column order.
COL_SIGNATURE = 8
COL_TLSH = 13


def normalize_tlsh(t):
    """Return a canonical 'T1...' (72 char) TLSH, or None if not a TLSH."""
    t = (t or "").strip().strip('"').strip()
    if not t or t.upper() in ("TNULL", "N/A", "-", ""):
        return None
    if t.startswith("T1") and len(t) == 72 and _hex(t[2:]):
        return t
    # Older bare 70-hex form -> add the T1 version prefix.
    if len(t) == 70 and _hex(t):
        return "T1" + t.upper()
    return None


def _hex(s):
    return all(c in "0123456789abcdefABCDEF" for c in s)


def _find_tlsh(row):
    """Prefer the known column; fall back to scanning the row (column drift)."""
    if len(row) > COL_TLSH:
        t = normalize_tlsh(row[COL_TLSH])
        if t:
            return t
    for field in row:
        t = normalize_tlsh(field)
        if t:
            return t
    return None


def parse_csv(text):
    out = []
    for row in csv.reader(io.StringIO(text), skipinitialspace=True):
        if not row or row[0].lstrip().startswith("#"):
            continue
        tl = _find_tlsh(row)
        if not tl:
            continue
        sig = ""
        if len(row) > COL_SIGNATURE:
            sig = row[COL_SIGNATURE].strip().strip('"').strip()
        out.append((tl, sig or "Malware"))
    return out


def fetch():
    req = urllib.request.Request(URL, headers={"User-Agent": "AetherAV/1.0"})
    key = os.environ.get("ABUSE_CH_AUTH_KEY")
    if key:
        req.add_header("Auth-Key", key)
    data = urllib.request.urlopen(req, timeout=180).read()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        return z.read(z.namelist()[0]).decode("utf-8", "replace")
    except zipfile.BadZipFile:
        return data.decode("utf-8", "replace")


def selftest():
    sample = (
        '#comment line\n'
        '"2024-01-01 00:00:00","aa","md5","sha1","rep","x.exe","exe",'
        '"application/x-dosexec","AgentTesla","Win.Trojan","60","imp","ssd",'
        '"T11D51977F006A2DF69144B08CA3E261B4FB30480AEEE87BF1029F44ACCD148EA042D21B"\n'
    )
    rows = parse_csv(sample)
    assert rows == [("T11D51977F006A2DF69144B08CA3E261B4FB30480AEEE87BF1029F44ACCD148EA042D21B", "AgentTesla")], rows
    assert normalize_tlsh("TNULL") is None and normalize_tlsh("n/a") is None
    assert normalize_tlsh("A" * 70) == "T1" + "A" * 70  # bare 70-hex gets T1 prefix
    print("selftest OK")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        text = open(args[0], encoding="utf-8", errors="replace").read()
    else:
        if not os.environ.get("ABUSE_CH_AUTH_KEY"):
            print("note: MalwareBazaar needs a free Auth-Key - set ABUSE_CH_AUTH_KEY "
                  "(https://auth.abuse.ch/) or pass a local CSV.", file=sys.stderr)
        try:
            text = fetch()
        except Exception as e:
            sys.exit(f"download failed: {e}")
    rows = parse_csv(text)
    seen = {}
    for tl, sig in rows:
        seen.setdefault(tl, sig)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w") as f:
        for tl, sig in seen.items():
            f.write(f"{tl}  {sig}\n")
    print(f"wrote {len(seen)} TLSH digests to {OUT}")


if __name__ == "__main__":
    main()
