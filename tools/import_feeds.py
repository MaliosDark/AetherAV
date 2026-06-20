#!/usr/bin/env python3
"""Import extra FREE, no-key, redistributable threat feeds into the AetherAV
intel store - more malicious IPs/domains on top of the abuse.ch + ClamAV data.

  python3 tools/import_feeds.py

For MILLIONS more malware hashes, also set a free abuse.ch key and run:
  ABUSE_CH_AUTH_KEY=<key> ABUSE_CH_FULL=1 ./tools/update-intel.sh
(get the free key at https://auth.abuse.ch/)
"""
import json, os, subprocess, sys, tempfile, urllib.request

AETHER = os.environ.get("AETHER_BIN")
for cand in ([AETHER] if AETHER else []) + ["target/release/aether", "target/debug/aether"]:
    if cand and os.path.exists(cand):
        AETHER = cand
        break
else:
    sys.exit("build the engine first: cargo build --release -p aether-cli")

STORE = os.environ.get("AETHER_INTEL", "assets/models/intel.json")

# (name, format, url) - all free, no key, redistributable threat lists.
FEEDS = [
    # ---- Malicious IPs ----
    ("cins-army",        "iplist",     "https://cinsscore.com/list/ci-badguys.txt"),
    ("blocklist.de",     "iplist",     "https://lists.blocklist.de/lists/all.txt"),
    ("et-compromised",   "iplist",     "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    ("greensnow",        "iplist",     "https://blocklist.greensnow.co/greensnow.txt"),
    ("digitalside-ips",  "iplist",     "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"),
    ("spamhaus-drop",    "spamhaus",   "https://www.spamhaus.org/drop/drop_v4.json"),
    # ---- Malicious / malware-hosting / phishing domains ----
    ("urlhaus-domains",  "domainlist", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt"),
    ("phishing-filter",  "domainlist", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt"),
    ("phishing-army",    "domainlist", "https://phishing.army/download/phishing_army_blocklist.txt"),
    ("digitalside-doms", "domainlist", "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"),
    # ---- Malware file hashes (SHA-256) ----
    ("digitalside-hash", "sha256",     "https://osint.digitalside.it/Threat-Intel/lists/latesthashes.txt"),
]

ua = {"User-Agent": "AetherAV-feeds/1.0"}
for name, fmt, url in FEEDS:
    try:
        req = urllib.request.Request(url, headers=ua)
        data = urllib.request.urlopen(req, timeout=40).read()
    except Exception as e:
        print(f"  skip {name}: {e}")
        continue
    # Spamhaus DROP ships JSON lines ({"cidr": "..."}); flatten to a CIDR list.
    if fmt == "spamhaus":
        cidrs = []
        for ln in data.decode("utf-8", "replace").splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    c = json.loads(ln).get("cidr")
                    if c:
                        cidrs.append(c)
                except ValueError:
                    pass
        data = "\n".join(cidrs).encode()
        fmt = "iplist"
    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as fh:
        fh.write(data)
        path = fh.name
    r = subprocess.run(
        [AETHER, "intel", "import", path, "--format", fmt, "--threat", name, "--store", STORE],
        capture_output=True, text=True)
    os.unlink(path)
    out = (r.stdout or r.stderr).strip().splitlines()
    print(f"  {name}: {out[-1] if out else 'no output'}")

print("done.")
