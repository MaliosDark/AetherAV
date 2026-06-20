import React, { useState, useEffect, useRef } from 'react'
import shot from './app-screenshot.jpg'
import logo from './aetherav.png'
import wordmark from './aethertext.png'

/* Canonical project links. */
const REPO = 'https://github.com/MaliosDark/AetherAV'
const RELEASES = REPO + '/releases/latest'
const DOC = p => `${REPO}/blob/main/${p}`

/* ---- tiny inline icon set (feather-style) ---- */
const P = {
  shield: 'M12 3 20 6v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z',
  brain: 'M9 4a3 3 0 0 0-3 3 3 3 0 0 0-1 5 3 3 0 0 0 2 4 3 3 0 0 0 5 1V5a3 3 0 0 0-3-1zM15 4a3 3 0 0 1 3 3 3 3 0 0 1 1 5 3 3 0 0 1-2 4 3 3 0 0 1-5 1',
  lock: 'M5 11h14v9H5zM8 11V8a4 4 0 0 1 8 0v3',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z',
  layers: 'M12 3 20 7l-8 4-8-4zM4 12l8 4 8-4M4 17l8 4 8-4',
  bolt: 'M13 2 4 14h6l-1 8 9-12h-6z',
  fingerprint: 'M5 11a7 7 0 0 1 13-3M6 15a10 10 0 0 0 1 4M12 11v3a6 6 0 0 0 2 4M9 19a8 8 0 0 1-1-6 4 4 0 0 1 8 0',
  refresh: 'M20 11a8 8 0 0 0-14-4M4 6v4h4M4 13a8 8 0 0 0 14 4M20 18v-4h-4',
  rotate: 'M3 12a9 9 0 1 0 3-6.7L3 8M3 4v4h4',
  check: 'M20 6 9 17l-5-5',
  cpu: 'M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3M6 6h12v12H6zM9 9h6v6H9z',
  code: 'M8 6 2 12l6 6M16 6l6 6-6 6',
  server: 'M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-4.3-4.3',
  ghost: 'M5 21V10a7 7 0 0 1 14 0v11l-3-2-2 2-2-2-2 2-3-2zM9 10h.01M15 10h.01',
  net: 'M5 12a7 7 0 0 1 14 0M2 12h2M20 12h2M12 5V3M6.3 6.3 4.9 4.9M17.7 6.3l1.4-1.4M12 12a5 5 0 0 1 0 8',
  download: 'M12 3v12M7 11l5 5 5-5M5 21h14',
  book: 'M4 4h11a3 3 0 0 1 3 3v13a2 2 0 0 0-2-2H4zM18 4h2v14',
  scale: 'M12 3v18M7 7l-4 7h8zM17 7l-4 7h8M5 21h14',
  github: 'M12 2a10 10 0 0 0-3 19.5c.5 0 .7-.2.7-.5v-2c-2.8.6-3.4-1.3-3.4-1.3-.5-1.2-1.1-1.5-1.1-1.5-.9-.6 0-.6 0-.6 1 .1 1.5 1 1.5 1 .9 1.6 2.4 1.1 3 .8.1-.6.3-1.1.6-1.4-2.2-.2-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.7 1a9.3 9.3 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.4.2 2.4.1 2.7.6.7 1 1.6 1 2.7 0 3.9-2.4 4.8-4.6 5 .3.3.6.9.6 1.8v2.7c0 .3.2.6.7.5A10 10 0 0 0 12 2z',
}
const Icon = ({ d, s = 22, c }) => (
  <svg viewBox="0 0 24 24" width={s} height={s} fill="none" stroke={c || 'currentColor'}
       strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d={P[d]} />
  </svg>
)

const FEATURES = [
  { i: 'layers', t: 'Ten layers of defense', d: 'Every file is checked by ten independent engines. If even one looks suspicious, the threat is caught.' },
  { i: 'brain', t: 'Smart AI, on your device', d: 'An AI brain spots brand-new threats right on your computer - your files never leave your machine.' },
  { i: 'rotate', t: 'Beats ransomware', d: 'Catches file-encrypting attacks in the act, stops them, and restores your files.' },
  { i: 'fingerprint', t: 'Protects your money', d: 'Traps the malware that steals crypto wallets, passwords and logins, and guards your clipboard.' },
  { i: 'bolt', t: 'Real-time protection', d: 'Scans files the moment they open and blocks threats before they can run.' },
  { i: 'ghost', t: 'Finds hidden malware', d: 'Uncovers rootkits and in-memory threats that try to stay invisible.' },
  { i: 'net', t: 'Firewall & web shield', d: 'Stops your PC from connecting to malicious servers and phishing sites.' },
  { i: 'refresh', t: 'Tamper-proof updates', d: 'Updates are digitally signed, so a hacked server can never push you a fake one.' },
  { i: 'lock', t: 'Private by design', d: 'Works fully offline and never tracks you. No ads, no data selling, no upsells.' },
  { i: 'cpu', t: 'Light and free', d: 'Tiny, fast and completely free - it protects without slowing you down.' },
]

const ENGINES = [
  ['Hash + Bloom filter', '1.6M+ known-malware hashes (MD5 / SHA-1 / SHA-256) with a fast Bloom pre-filter.'],
  ['YARA-X rules', '28 in-house pattern rules: webshells, injectors, ransomware, C2 beacons.'],
  ['ClamAV pattern engine', '106k ClamAV-format hex signatures to catch malware variants.'],
  ['Static heuristics', 'Entropy, packing, W^X and suspicious-import structural analysis.'],
  ['Static ML', 'A logistic PE classifier over 12 structural features.'],
  ['Aegis-50M AI', 'On-device model that reads commands & scripts and explains the verdict.'],
  ['Sandbox / emulation', 'x86 / x64 disassembly that spots shellcode and anti-analysis tricks.'],
  ['Behavioral graph', 'MITRE ATT&CK rules over process / file / network event graphs.'],
  ['Anomaly engine', 'A per-host baseline that flags never-before-seen behavior.'],
  ['Threat-intel IOCs', '22k+ signed indicators: hashes, domains, URLs and IPs.'],
]

const REALTIME = [
  ['On-access blocking', 'Kernel fanotify checks every open / exec and blocks before code runs.'],
  ['Memory / fileless scan', 'Finds injected and in-memory code (W^X, unbacked executable maps).'],
  ['Ransomware rollback', 'Canaries + snapshots detect mass-encryption and restore your files.'],
  ['Process Sentinel', 'Catches new apps by hash and hidden (rootkit) processes.'],
  ['Kernel exec tracer', 'cn_proc exec events that resist userland hiding.'],
  ['Smart firewall', 'Blocks connections to malicious IPs/ports via the OS native firewall (nftables/netsh/pf).'],
  ['Web / phishing block', 'Sinkholes malicious domains locally in the hosts file - no cloud, fully private.'],
  ['Stealer & wallet shield', 'Decoy wallet/credential files trap infostealers, then block the source process.'],
  ['Network monitor', 'Flags connections to known malware ports and bad IPs.'],
  ['Self-protection', 'Anti-tamper hardening plus a signed integrity manifest.'],
]

const PILLARS = [
  { i: 'github', t: 'Free & open source', d: 'Every line of code and every signature is public. Auditable by anyone, beholden to no one - no upsells, no bundled VPN, no data resale.' },
  { i: 'lock', t: 'Private by architecture', d: 'Your files never leave your machine - not because we promise, but because the AI runs locally and there is no cloud to send them to.' },
  { i: 'brain', t: 'AI-modern, not signature-only', d: 'An on-device model catches obfuscated and never-before-seen attacks that signature-only engines like ClamAV miss.' },
  { i: 'refresh', t: 'Tamper-proof by design', d: 'Signed feeds, model and releases plus reproducible builds. A compromised server still cannot push you malware.' },
]

const PIPELINE = ['Hash match', 'YARA rules', 'Patterns', 'Parsers', 'Heuristics', 'Static ML', 'Aegis AI', 'Sandbox', 'Anomaly', 'Intel IOC']

const STATS = [
  ['1.6M+', 'Malware signatures'],
  ['10', 'Detection engines'],
  ['~0%', 'False positives'],
  ['50M', 'On-device AI model'],
]

const BENCH = [
  ['100%', 'Detection rate', 'On our internal malware + EICAR test set.'],
  ['0%', 'False positives', '0 flagged across 500 real system binaries (down from ~40%).'],
  ['~8s', 'Cold-start load', 'All engines load concurrently at startup.'],
  ['36 MB', 'AI footprint', 'Aegis-50M runs CPU-only, no GPU, no cloud.'],
]

// Visual trust seals - our own honest claims (no third-party award logos).
const SEALS = [
  ['shield', 'Open Source', 'no black box'],
  ['brain', 'On-device AI', 'no cloud'],
  ['lock', 'Private', 'no tracking'],
  ['rotate', 'Anti-ransomware', 'restores files'],
  ['refresh', 'Auto-updating', 'tamper-proof'],
  ['bolt', 'Light & fast', 'low impact'],
]

const DOWNLOADS = [
  ['Windows', 'Installer wizard with license & components, real-time protection, desktop app + CLI.', 'AetherAV-Setup.exe', true],
  ['macOS', 'Signed .pkg wizard (or .dmg), universal Intel + Apple Silicon, with LaunchDaemon real-time.', 'AetherAV.pkg', true],
  ['Linux', '.deb package or install.sh; kernel-level real-time (fanotify) + auto-updates.', 'aetherav.deb', true],
]

const FAQ = [
  ['Is it really free?', 'Yes - free and open source, forever. There is no paid tier you need to unlock, no upsells, and no bundled extras you did not ask for.'],
  ['Does my data leave my computer?', 'No. AetherAV is offline by default and the AI runs on your own CPU. Sharing a sample is strictly opt-in, anonymous and send-only - we only ever receive what you choose to send.'],
  ['How is it different from ClamAV?', 'ClamAV is essentially signature-only. AetherAV adds an on-device AI classifier, behavioral detection, anti-ransomware rollback, anti-rootkit scanning and memory/fileless detection on top of signatures.'],
  ['Does the AI need internet or a GPU?', 'Neither. Aegis-50M is a 36 MB model that runs on a normal CPU, completely offline. No accelerator and no network connection required.'],
  ['Which operating systems are supported?', 'The scan engine, CLI and desktop app run on Windows, macOS and Linux. Kernel-level real-time protection ships on Linux today; Windows and macOS are next.'],
  ['Can a hacked server push me malware?', 'No. Every feed, model and release is Ed25519-signed with a key that lives offline. AetherAV refuses anything it cannot verify, and updates can only move forward, never roll back.'],
  ['Does it protect against crypto theft?', 'Yes. AetherAV plants decoy wallet/credential files to trap infostealers, detects processes scraping wallet keys or seed phrases from memory, and guards the clipboard against address-swapping "clippers".'],
  ['Will it slow down my computer?', 'It is built in Rust and engineered to be light: a 36 MB AI model that runs on the CPU, a Bloom-filtered hash database, and a scan cache that skips files it has already seen. No bundled bloatware.'],
  ['Is the AI a chatbot?', 'No. Aegis-50M is a focused detection model - it reads commands and scripts and outputs a verdict with a MITRE technique and reason. It is a tool, not an assistant, which is why it stays tiny and fast.'],
  ['How does it update?', 'Signatures auto-update on a schedule (and on demand), each batch Ed25519-verified before it is applied. The AI model updates the same way, with an anti-rollback check, swapped in atomically.'],
  ['Do you offer an enterprise / EDR console?', 'Not yet, and we say so plainly. AetherAV focuses on being the best free, private endpoint engine; a central management console is on the roadmap, not a hidden upsell.'],
  ['Is it ready to replace my antivirus?', 'It is a strong, modern engine and excellent defense in depth - especially on Linux. Independent lab certification (AV-TEST / AV-Comparatives) is on the roadmap; until then we publish our own measured numbers, honestly.'],
]

/* AetherAV vs ClamAV vs Defender vs Bitdefender vs CrowdStrike - honest. */
const CMP_COLS = ['AetherAV', 'ClamAV', 'Defender', 'Bitdefender', 'CrowdStrike']
const CMP_ROWS = [
  ['Open source & auditable', 'yes', 'yes', 'no', 'no', 'no'],
  ['Free', 'yes', 'yes', 'yes', 'partial', 'no'],
  ['On-device AI detection', 'yes', 'no', 'yes', 'yes', 'yes'],
  ['Behavioral / heuristic', 'yes', 'partial', 'yes', 'yes', 'yes'],
  ['Anti-ransomware rollback', 'yes', 'no', 'no', 'yes', 'no'],
  ['Anti-rootkit / hidden-process', 'yes', 'no', 'yes', 'yes', 'yes'],
  ['Fileless / in-memory scan', 'yes', 'no', 'yes', 'yes', 'yes'],
  ['Real-time on-access', 'yes', 'yes', 'yes', 'yes', 'yes'],
  ['Threat-intel firewall', 'yes', 'no', 'yes', 'partial', 'yes'],
  ['Web / phishing protection', 'yes', 'partial', 'yes', 'yes', 'partial'],
  ['Anti-infostealer decoys', 'yes', 'no', 'no', 'partial', 'partial'],
  ['Sandbox / emulation', 'yes', 'partial', 'yes', 'yes', 'yes'],
  ['EDR / threat hunting', 'no', 'no', 'yes', 'yes', 'yes'],
  ['Local-first / no cloud telemetry', 'yes', 'yes', 'no', 'partial', 'no'],
  ['Signed, tamper-proof updates', 'yes', 'yes', 'yes', 'yes', 'partial'],
  ['Reproducible builds', 'yes', 'partial', 'no', 'no', 'no'],
  ['Signature database', '1.6M+', '8M+', 'Cloud', 'Hybrid', 'AI-driven'],
]

function Nav() {
  return (
    <nav className="nav">
      <div className="wrap nav-in">
        <a className="brand" href="#">
          <img className="brand-logo-img" src={logo} alt="AetherAV logo" />
          <img className="brand-wordmark" src={wordmark} alt="AetherAV" />
        </a>
        <div className="nav-links">
          <a href="#features">Features</a>
          <a href="#engines">Engines</a>
          <a href="#live">Live</a>
          <a href="#ai">Aegis AI</a>
          <a className="btn btn-ghost" href={REPO} target="_blank" rel="noopener"><Icon d="github" s={16} /> GitHub</a>
          <a className="btn btn-primary" href={RELEASES} target="_blank" rel="noopener">Download</a>
        </div>
      </div>
    </nav>
  )
}

function Hero() {
  return (
    <header className="hero" id="top">
      <div className="wrap hero-in">
        <div className="hero-copy">
          <span className="eyebrow">FREE · PRIVATE · OPEN SOURCE</span>
          <h1>Powerful protection.<br /><span className="grad">Total privacy.</span></h1>
          <p className="lead">
            AetherAV stops viruses, ransomware and the malware that goes after your
            crypto wallets, passwords and files - with smart AI that runs on your
            own device and never spies on you. Completely free.
          </p>
          <div className="hero-cta">
            <a className="btn btn-primary lg" href="#download">Download free</a>
            <a className="btn btn-ghost lg" href={REPO} target="_blank" rel="noopener"><Icon d="github" s={18} /> View source</a>
          </div>
          <div className="chips">
            <span><Icon d="check" s={14} /> Free forever</span>
            <span><Icon d="check" s={14} /> Never spies on you</span>
            <span><Icon d="check" s={14} /> Light on your PC</span>
            <span><Icon d="check" s={14} /> Catches brand-new threats</span>
          </div>
        </div>
        <div className="hero-art">
          <div className="radar">
            <span className="ring r1" /><span className="ring r2" /><span className="ring r3" />
            <img className="radar-logo" src={logo} alt="AetherAV" />
          </div>
        </div>
      </div>
    </header>
  )
}

function Stats() {
  // Live from the production API (JWT-authed). Falls back to STATS when offline.
  const [s, setS] = useState(null)
  useEffect(() => {
    let on = true
    const load = async () => { const d = await jget('/api/stats'); if (on && d) setS(d) }
    load()
    const t = setInterval(load, 60000)
    return () => { on = false; clearInterval(t) }
  }, [])
  const rows = s
    ? [
        [fmt(s.hashes) + '+', 'Malware signatures'],
        [fmt(s.iocs) + '+', 'Threat-intel IOCs'],
        [String(s.yara_rules), 'YARA rules'],
        [s.model && s.model.present ? '50M' : '—', 'On-device AI model'],
      ]
    : STATS
  return (
    <section className="stats wrap">
      {rows.map(([v, l]) => (
        <div className="stat" key={l}><div className="sv">{v}</div><div className="sl">{l}</div></div>
      ))}
    </section>
  )
}

function Features() {
  return (
    <section className="section wrap" id="features">
      <h2>One scan. Ten ways to catch it.</h2>
      <p className="section-sub">Defense in depth: static, behavioral, and AI layers working together. Beating one is not enough.</p>
      <div className="cards">
        {FEATURES.map(f => (
          <div className="card" key={f.t}>
            <span className="card-ic"><Icon d={f.i} s={22} /></span>
            <div className="card-t">{f.t}</div>
            <div className="card-d">{f.d}</div>
          </div>
        ))}
      </div>
    </section>
  )
}

function Engines() {
  return (
    <section className="section wrap" id="engines">
      <h2>Inside the engine</h2>
      <p className="section-sub">Ten independent detection layers, plus real-time protection that stops threats while they run.</p>
      <div className="eng-wrap">
        <div className="eng-col">
          <div className="eng-head"><Icon d="search" s={18} /> Detection layers</div>
          {ENGINES.map(([t, d]) => (
            <div className="eng-item" key={t}><b>{t}</b><span>{d}</span></div>
          ))}
        </div>
        <div className="eng-col">
          <div className="eng-head"><Icon d="bolt" s={18} /> Real-time protection <em>(Linux)</em></div>
          {REALTIME.map(([t, d]) => (
            <div className="eng-item" key={t}><b>{t}</b><span>{d}</span></div>
          ))}
          <p className="eng-note">Core scanning, CLI, daemon and desktop app run on Windows, macOS and Linux. Kernel-level real-time protection ships on Linux today; Windows and macOS are next.</p>
        </div>
      </div>
    </section>
  )
}

function Cell({ v, own }) {
  const cls = own ? ' own' : ''
  if (v === 'yes') return <td className={'c-yes' + cls}><Icon d="check" s={18} /></td>
  if (v === 'no') return <td className={'c-no' + cls}>-</td>
  if (v === 'partial') return <td className={'c-part' + cls}>Partial</td>
  return <td className={'c-txt' + cls}>{v}</td>
}

function Compare() {
  return (
    <section className="section wrap" id="compare">
      <h2>How it compares</h2>
      <p className="section-sub">Side by side, honestly. We are the only one that is open source <b>and</b> AI-modern <b>and</b> private. ClamAV ships more raw signatures but has none of the modern layers; the big suites are powerful but closed and cloud-bound.</p>
      <div className="compare">
        <table>
          <thead>
            <tr><th /><th className="own">AetherAV</th>{CMP_COLS.slice(1).map(c => <th key={c}>{c}</th>)}</tr>
          </thead>
          <tbody>
            {CMP_ROWS.map(r => (
              <tr key={r[0]}>
                <th scope="row">{r[0]}</th>
                <Cell v={r[1]} own />
                {r.slice(2).map((v, i) => <Cell v={v} key={i} />)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="compare-note">Reflects default, out-of-the-box capabilities as of 2026. "Defender" = Microsoft Defender Antivirus; "CrowdStrike" = Falcon. We do not ship a full EDR/threat-hunting console - and we say so.</p>
    </section>
  )
}

function Pillars() {
  return (
    <section className="section wrap" id="why">
      <h2>Free. Community. Secure.</h2>
      <p className="section-sub">The combination no incumbent offers: open source, on-device AI, and privacy you can verify - not just trust.</p>
      <div className="pillars">
        {PILLARS.map(p => (
          <div className="pillar" key={p.t}>
            <span className="card-ic"><Icon d={p.i} s={22} /></span>
            <div className="card-t">{p.t}</div>
            <div className="card-d">{p.d}</div>
          </div>
        ))}
      </div>
    </section>
  )
}

function How() {
  return (
    <section className="section wrap" id="how">
      <h2>How it works</h2>
      <p className="section-sub">Every file flows through independent engines. An exact hit stops instantly; otherwise the layers vote and the worst verdict wins.</p>
      <div className="pipe">
        <div className="pipe-node file">File</div>
        <span className="pipe-arrow">&rsaquo;</span>
        {PIPELINE.map((p, i) => (
          <React.Fragment key={p}>
            <div className="pipe-node">{p}</div>
            {i < PIPELINE.length - 1 && <span className="pipe-arrow">&rsaquo;</span>}
          </React.Fragment>
        ))}
        <span className="pipe-arrow">&rsaquo;</span>
        <div className="pipe-node verdict">Verdict</div>
      </div>
    </section>
  )
}

function Showcase() {
  return (
    <section className="section wrap" id="screenshot">
      <h2>See it in action</h2>
      <p className="section-sub">The AetherAV desktop app - protection status, system health, MITRE mappings, quarantine and threat-intel at a glance.</p>
      <div className="shot-frame">
        <div className="pv-bar"><span /><span /><span /> AetherAV - Dashboard</div>
        <img src={shot} alt="AetherAV desktop application dashboard" loading="lazy" />
      </div>
    </section>
  )
}

function Bench() {
  return (
    <section className="section wrap" id="benchmarks">
      <h2>Measured, not marketed</h2>
      <p className="section-sub">Real numbers from our own evaluation harness - reproduce them yourself with <code>tools/benchmark.sh</code>.</p>
      <div className="seals">
        {SEALS.map(([i, t, s]) => (
          <div className="seal" key={t}>
            <div className="seal-ring"><Icon d={i} s={24} /></div>
            <div className="seal-t">{t}</div>
            <div className="seal-s">{s}</div>
          </div>
        ))}
      </div>
      <div className="cards bench">
        {BENCH.map(([v, t, d]) => (
          <div className="card bcard" key={t}>
            <div className="bval">{v}</div>
            <div className="card-t">{t}</div>
            <div className="card-d">{d}</div>
          </div>
        ))}
      </div>
    </section>
  )
}

function Downloads() {
  return (
    <section className="section wrap" id="download">
      <h2>Get AetherAV</h2>
      <p className="section-sub">Free and open source. Download a build, or compile it yourself - bit-for-bit reproducible.</p>
      <div className="dl-grid">
        {DOWNLOADS.map(([os, note, file, full]) => (
          <div className="dl-card" key={os}>
            <div className="dl-os">{os}{full && <span className="dl-tag">Full</span>}</div>
            <div className="dl-note">{note}</div>
            <a className="btn btn-primary" href={RELEASES} target="_blank" rel="noopener"><Icon d="download" s={16} /> Download</a>
            <div className="dl-file">{file}</div>
          </div>
        ))}
      </div>
      <div className="dl-build">
        <div className="dl-build-h">Or build from source</div>
        <pre><code>{`git clone https://github.com/aetherav/aetherav
cd aetherav && cargo build --release
./target/release/aether scan ~/Downloads`}</code></pre>
      </div>
    </section>
  )
}

function Faq() {
  return (
    <section className="section wrap" id="faq">
      <h2>Questions, answered</h2>
      <div className="faq">
        {FAQ.map(([q, a]) => (
          <details key={q}>
            <summary>{q}<span className="faq-plus">+</span></summary>
            <p>{a}</p>
          </details>
        ))}
      </div>
    </section>
  )
}

function CTA() {
  return (
    <section className="cta">
      <div className="wrap cta-in">
        <h2>Protection you can read, build, and verify.</h2>
        <p>Free and open source. Download it, or compile it yourself - bit-for-bit reproducible.</p>
        <div className="hero-cta">
          <a className="btn btn-primary lg" href={RELEASES} target="_blank" rel="noopener">Download free</a>
          <a className="btn btn-ghost lg" href={REPO} target="_blank" rel="noopener"><Icon d="github" s={18} /> Star on GitHub</a>
        </div>
      </div>
    </section>
  )
}

const FOOT = [
  ['Product', [['Features', '#features'], ['Engines', '#engines'], ['Live threat feed', '#live'], ['Aegis AI', '#ai'], ['Download', RELEASES]]],
  ['Project', [['GitHub', REPO], ['Roadmap', DOC('docs/ROADMAP.md')], ['Changelog', DOC('CHANGELOG.md')], ['License', DOC('LICENSE')], ['Contributing', DOC('CONTRIBUTING.md')]]],
  ['Security', [['Security policy', DOC('SECURITY.md')], ['Verify releases', DOC('docs/VERIFY.md')], ['Report a vulnerability', REPO + '/security/advisories/new'], ['Certification', DOC('docs/CERTIFICATION.md')]]],
]

function Footer() {
  return (
    <footer className="footer">
      <div className="wrap foot-in">
        <div className="foot-brand">
          <div className="brand"><img className="brand-logo-img sm" src={logo} alt="AetherAV" /><img className="brand-wordmark" src={wordmark} alt="AetherAV" /></div>
          <p className="muted">The open-source antivirus that fights back. On-device AI, behavioral defense, tamper-proof updates - free and private by design.</p>
          <div className="foot-tags"><span><Icon d="check" s={13} /> Built in Rust</span><span><Icon d="check" s={13} /> Reproducible builds</span></div>
        </div>
        {FOOT.map(([h, links]) => (
          <div className="foot-col" key={h}>
            <div className="foot-h">{h}</div>
            {links.map(([t, href]) => {
              const ext = href.startsWith('http')
              return <a key={t} href={href} {...(ext ? { target: '_blank', rel: 'noopener' } : {})}>{t}</a>
            })}
          </div>
        ))}
      </div>
      <div className="wrap foot-bottom">
        <span>© 2026 AetherAV - open source.</span>
        <span>Local-first · On-device AI · No telemetry</span>
      </div>
    </footer>
  )
}

/* ---------- Aegis AI page (separate route: #ai) ---------- */

const AI_SPECS = [
  ['50M', 'Parameters'],
  ['36 MB', 'On disk'],
  ['0', 'Cloud calls'],
  ['CPU', 'No GPU needed'],
]

const AI_STEPS = [
  ['Suspicious artifact', 'A command line, script, or behavior summary reaches the AI layer.'],
  ['Read locally', 'Aegis-50M runs on your CPU via llama.cpp - nothing is uploaded.'],
  ['Explainable verdict', 'It returns Malicious / Suspicious plus a MITRE ATT&CK technique and a one-line reason.'],
  ['Fused with 9 engines', 'Its verdict joins the other layers; the worst verdict wins.'],
]

const AI_WHY = [
  { i: 'bolt', t: 'Pre-execution', d: 'Judges intent before code runs - no need to wait for damage or a matching signature.' },
  { i: 'refresh', t: 'No signature treadmill', d: 'Understands obfuscation and intent instead of chasing one hash at a time.' },
  { i: 'search', t: 'Catches the never-before-seen', d: 'Generalizes to novel and AI-generated attacks that signature-only AV misses.' },
  { i: 'lock', t: 'Private by design', d: 'Runs entirely on-device. There is no cloud, so your files cannot be sent anywhere.' },
  { i: 'cpu', t: 'Tiny and fast', d: '36 MB, CPU-only. It rides along with the engine instead of needing a datacenter.' },
  { i: 'code', t: 'Explainable', d: 'Every AI verdict comes with a MITRE technique and a human-readable reason.' },
]

function AiPage() {
  return (
    <main className="ai">
      <header className="hero ai-hero">
        <div className="wrap hero-in">
          <div className="hero-copy">
            <span className="eyebrow">AEGIS-50M · ON-DEVICE AI</span>
            <h1>An antivirus with a brain -<br /><span className="grad">that never phones home.</span></h1>
            <p className="lead">
              Aegis-50M is a compact, 50-million-parameter detection model built into AetherAV.
              It reads commands and scripts, understands intent, and explains its verdict -
              running entirely on your CPU, fully offline.
            </p>
            <div className="hero-cta">
              <a className="btn btn-primary lg" href={RELEASES} target="_blank" rel="noopener">Download free</a>
              <a className="btn btn-ghost lg" href="#top">Back to overview</a>
            </div>
          </div>
          <div className="hero-art">
            <div className="radar">
              <span className="ring r1" /><span className="ring r2" /><span className="ring r3" />
              <div className="shield"><Icon d="brain" s={86} c="#2ee6d6" /></div>
            </div>
          </div>
        </div>
      </header>

      <section className="stats wrap">
        {AI_SPECS.map(([v, l]) => (
          <div className="stat" key={l}><div className="sv">{v}</div><div className="sl">{l}</div></div>
        ))}
      </section>

      <section className="section wrap">
        <h2>How Aegis thinks</h2>
        <p className="section-sub">Not a chatbot - a focused detector. It is trained to do one thing well: judge whether code is hostile, and say why.</p>
        <div className="ai-steps">
          {AI_STEPS.map(([t, d], i) => (
            <div className="ai-step" key={t}>
              <div className="ai-num">{i + 1}</div>
              <div><b>{t}</b><p>{d}</p></div>
            </div>
          ))}
        </div>
      </section>

      <section className="section wrap">
        <h2>Why on-device AI beats legacy AV</h2>
        <p className="section-sub">Signature-only engines are reactive - they only know yesterday's malware. Aegis judges intent, today, on your machine.</p>
        <div className="cards">
          {AI_WHY.map(f => (
            <div className="card" key={f.t}>
              <span className="card-ic"><Icon d={f.i} s={22} /></span>
              <div className="card-t">{f.t}</div>
              <div className="card-d">{f.d}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="section wrap">
        <div className="ai-train">
          <h2>Trained in the open, shipped with proof</h2>
          <p>
            Aegis is fine-tuned on a curated dataset of commands and scripts labelled with verdict,
            MITRE technique and reason, then exported to a quantized GGUF model that runs through
            llama.cpp. It is deliberately small - a detection tool, not a chatbot - so it runs
            everywhere.
          </p>
          <p>
            Every model update is <b>Ed25519-signed and version-checked</b>: AetherAV only loads a
            model whose signature matches our offline key, so a compromised server can never swap in
            a poisoned brain. Open dataset, open code, verifiable updates.
          </p>
        </div>
      </section>

      <CTA />
    </main>
  )
}

/* ---------- router ---------- */

function useRoute() {
  const read = () => {
    const h = typeof window !== 'undefined' ? window.location.hash : ''
    if (h === '#ai') return 'ai'
    if (h === '#live') return 'live'
    return 'home'
  }
  const [route, setRoute] = useState(read())
  useEffect(() => {
    const onHash = () => { setRoute(read()); window.scrollTo(0, 0) }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])
  return route
}

function Home() {
  return (
    <>
      <Hero />
      <Stats />
      <Features />
      <Showcase />
      <Engines />
      <Compare />
      <Bench />
      <Pillars />
      <How />
      <Downloads />
      <Faq />
      <CTA />
    </>
  )
}

/* ============================ LIVE THREAT DASHBOARD ============================ */
/* Production backend (external nginx -> this PC's aether-site). Override at build:
   VITE_API_BASE=https://aether-central.aswss.com npm run build               */
const API = import.meta.env.VITE_API_BASE || 'https://aether-central.aswss.com'
// Optional shared client key (set VITE_CLIENT_KEY at build to match the server's
// AETHER_CLIENT_KEY) - an extra gate on top of the origin allowlist + JWT.
const CLIENT_KEY = import.meta.env.VITE_CLIENT_KEY || ''

// Short-lived JWT obtained from /api/auth (origin-gated, rate-limited). The
// browser sends the Origin header automatically, which the server enforces.
let _token = null, _exp = 0
async function authToken() {
  if (_token && Date.now() / 1000 < _exp - 30) return _token
  try {
    const r = await fetch(API + '/api/auth', { headers: CLIENT_KEY ? { 'X-Aether-Key': CLIENT_KEY } : {} })
    if (!r.ok) return null
    const j = await r.json()
    _token = j.token; _exp = j.exp
    return _token
  } catch (_) { return null }
}

async function jget(path) {
  try {
    let t = await authToken()
    const call = tk => fetch(API + path, { cache: 'no-store', headers: tk ? { Authorization: 'Bearer ' + tk } : {} })
    let r = await call(t)
    if (r.status === 401) { _token = null; t = await authToken(); r = await call(t) } // token expired -> refresh once
    if (!r.ok) return null
    return await r.json()
  } catch (_) { return null }
}

function useCountUp(target) {
  const [n, setN] = useState(0)
  useEffect(() => {
    if (!target) { setN(0); return }
    let raf
    const t0 = performance.now(), dur = 900
    const tick = t => {
      const k = Math.min(1, (t - t0) / dur)
      setN(Math.round(target * (1 - Math.pow(1 - k, 3))))
      if (k < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target])
  return n
}

const fmt = n => (n || 0).toLocaleString()
function ago(ts) {
  if (!ts) return ''
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts)
  if (s < 60) return s + 's ago'
  if (s < 3600) return Math.floor(s / 60) + 'm ago'
  if (s < 86400) return Math.floor(s / 3600) + 'h ago'
  return Math.floor(s / 86400) + 'd ago'
}

/* Tween a number toward its target. On mount it eases 0 -> value (a nice
   reveal); afterwards it animates only the DELTA (prev -> new), so live ticks
   "add on" smoothly instead of recounting the whole number from zero. */
function useTween(value) {
  const [disp, setDisp] = useState(0)
  const prev = useRef(0)
  useEffect(() => {
    const from = prev.current, to = value || 0
    prev.current = to
    if (from === to) { setDisp(to); return }
    let raf, t0
    const dur = Math.min(900, 240 + Math.abs(to - from) * 2)
    const step = t => {
      if (!t0) t0 = t
      const k = Math.min(1, (t - t0) / dur)
      setDisp(Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3))))
      if (k < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [value])
  return disp
}
function Counter({ value, label }) {
  const n = useTween(value)
  return <div className="stat"><div className="sv">{fmt(n)}</div><div className="sl">{label}</div></div>
}
function Num({ value, suffix }) {
  const n = useTween(value)
  return <>{fmt(n)}{suffix || ''}</>
}

function LivePage() {
  // All live activity is emitted by the server (/api/community): persistent,
  // identical for every visitor, and never resets on reload.
  const [stats, setStats] = useState(null)
  const [comm, setComm] = useState(null)
  const [news, setNews] = useState(null)
  const [online, setOnline] = useState(false)

  useEffect(() => {
    let on = true
    const tick = async () => {
      const c = await jget('/api/community')
      if (!on) return
      setOnline(!!c)
      if (c) setComm(c)
    }
    const slow = async () => {
      const [s, n] = await Promise.all([jget('/api/stats'), jget('/api/news')])
      if (!on) return
      if (s) setStats(s)
      if (n) setNews(n)
    }
    tick(); slow()
    const a = setInterval(tick, 4000), b = setInterval(slow, 60000)
    return () => { on = false; clearInterval(a); clearInterval(b) }
  }, [])

  const items = (comm && comm.feed) || []
  const fams = (comm && comm.families) || []
  const famMax = fams.reduce((m, f) => Math.max(m, f.count), 1)

  return (
    <main className="live-page">
      <section className="section wrap" style={{ paddingBottom: 0 }}>
        <div className="live-head">
          <span className={'live-badge' + (online ? '' : ' off')}>
            <span className="live-dot" />{online ? 'LIVE' : 'CONNECTING…'}
          </span>
          <h2 style={{ margin: '12px 0 4px' }}>AetherAV Threat Intelligence</h2>
          <p className="section-sub" style={{ margin: 0 }}>
            Real-time analysis from the community pipeline - anonymous submissions, scanned by all
            ten engines, with live verdicts.{online ? '' : ' Waiting for ' + API.replace(/^https?:\/\//, '') + '…'}
          </p>
        </div>

        <div className="stats" style={{ marginTop: 22 }}>
          <Counter value={stats ? stats.hashes : 0} label="Malware Hashes" />
          <Counter value={stats ? stats.iocs : 0} label="Threat-Intel IOCs" />
          <Counter value={stats ? stats.yara_rules : 0} label="YARA Rules" />
          <Counter value={stats ? stats.patterns : 0} label="Pattern Signatures" />
          <Counter value={comm ? comm.submissions : 0} label="Community Submissions" />
          <Counter value={comm ? comm.flagged : 0} label="Flagged Threats" />
        </div>
      </section>

      <section className="section wrap live-grid">
        <div className="panel-card">
          <div className="pc-head"><span className="live-dot sm" /> LIVE ANALYSIS FEED</div>
          <div className="feed">
            {items.length === 0 && <div className="feed-empty">Waiting for live submissions…</div>}
            {items.map((it, i) => (
              <div className={'feed-row ' + (it.verdict === 'malicious' ? 'mal' : 'pend')} key={(it.sha256 || '') + i}>
                <span className="fr-ic"><Icon d={it.verdict === 'malicious' ? 'search' : 'refresh'} s={15} /></span>
                <code className="fr-hash">{(it.short || (it.sha256 || '').slice(0, 12))}…</code>
                <span className={'fr-tag ' + (it.verdict === 'malicious' ? 't-mal' : 't-pend')}>
                  {it.verdict === 'malicious' ? 'Malicious' : 'Pending'}
                </span>
                <span className="fr-threat">{it.threat}</span>
                <span className="fr-time">{ago(it.ts)}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="live-col">
          <div className="panel-card">
            <div className="pc-head">TOP MALWARE FAMILIES</div>
            <div className="bars">
              {fams.length === 0 && <div className="feed-empty">No flagged families yet.</div>}
              {fams.map(f => (
                <div className="bar-row" key={f.name}>
                  <span className="bar-name">{f.name}</span>
                  <span className="bar-track"><span className="bar-fill" style={{ width: (f.count / famMax * 100) + '%' }} /></span>
                  <span className="bar-n">{f.count}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="panel-card">
            <div className="pc-head"><span className="live-dot sm" /> COMMUNITY PULSE</div>
            <div className="comm">
              <div className="comm-row"><span>Files analyzed today</span><b><Num value={comm ? comm.analyzed_today : 0} /></b></div>
              <div className="comm-row"><span>Active scanners</span><b><Num value={comm ? comm.scanners : 0} /></b></div>
              <div className="comm-row"><span>Countries protected</span><b>{comm ? comm.countries : 0}</b></div>
              <div className="comm-row"><span>Avg. verdict time</span><b><Num value={comm ? comm.verdict_ms : 0} suffix=" ms" /></b></div>
            </div>
            <div className="comm-foot"><span className="live-dot sm" /><Num value={comm ? comm.online : 0} />&nbsp;protections online now</div>
          </div>
        </div>
      </section>

      <section className="section wrap">
        <h2>Threat desk</h2>
        <p className="section-sub">Security news and practical advice{news && news.source === 'ollama' ? ' (AI-generated, grounded in live data)' : ''}.</p>
        <div className="news-grid">
          {news && (news.news || []).map((x, i) => (
            <div className="news-card" key={'n' + i}>
              <span className="news-kind kind-news">NEWS</span>
              <div className="news-t">{x.title}</div><div className="news-d">{x.summary}</div>
            </div>
          ))}
          {news && (news.advice || []).map((x, i) => (
            <div className="news-card" key={'a' + i}>
              <span className="news-kind kind-advice">ADVICE</span>
              <div className="news-t">{x.title}</div><div className="news-d">{x.summary}</div>
            </div>
          ))}
          {!news && <div className="feed-empty">Loading threat desk…</div>}
        </div>
      </section>
    </main>
  )
}

export default function App() {
  const route = useRoute()
  return (
    <>
      <Nav />
      {route === 'ai' ? <AiPage /> : route === 'live' ? <LivePage /> : <Home />}
      <Footer />
    </>
  )
}
