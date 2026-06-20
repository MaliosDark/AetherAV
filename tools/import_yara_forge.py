#!/usr/bin/env python3
"""Fetch the YARA-Forge ruleset - the best free, license-respecting YARA bundle
(thousands of rules aggregated from many vendors, per-rule licenses preserved,
Elastic-licensed rules auto-excluded) - into assets/community-rules/.

  python3 tools/import_yara_forge.py [core|extended|full]   (default: core)

OPT-IN by design: community-rules/ is NOT loaded by default. Review the rules,
then move the file into assets/rules/ to enable it (keeps our "own content by
default" stance and lets you vet third-party rules first).
"""
import io, os, sys, urllib.request, zipfile

LEVEL = (sys.argv[1] if len(sys.argv) > 1 else "core").lower()
if LEVEL not in ("core", "extended", "full"):
    sys.exit("level must be: core | extended | full")
URL = f"https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{LEVEL}.zip"
OUTDIR = "assets/community-rules"
OUTFILE = os.path.join(OUTDIR, f"yara-forge-{LEVEL}.yar")


def main():
    print(f"downloading YARA-Forge '{LEVEL}' from {URL} ...", file=sys.stderr)
    req = urllib.request.Request(URL, headers={"User-Agent": "AetherAV/1.0"})
    try:
        data = urllib.request.urlopen(req, timeout=180).read()
    except Exception as e:
        sys.exit(f"download failed: {e}")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        sys.exit("archive is not a valid zip (release asset name may have changed)")
    yar = [n for n in z.namelist() if n.endswith((".yar", ".yara"))]
    if not yar:
        sys.exit(f"no .yar file in the archive (contents: {z.namelist()[:5]})")
    text = "\n".join(z.read(n).decode("utf-8", "replace") for n in yar)
    os.makedirs(OUTDIR, exist_ok=True)
    with open(OUTFILE, "w") as f:
        f.write(text)
    rules = sum(1 for ln in text.splitlines() if ln.lstrip().startswith("rule "))
    print(f"wrote {rules} YARA-Forge rules to {OUTFILE}")
    print("OPT-IN: review, then move into assets/rules/ to load.")


if __name__ == "__main__":
    main()
