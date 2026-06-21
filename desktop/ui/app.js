/* ================= AetherAV desktop UI logic ================= */

// --- Inline icon set (feather-style stroke icons) ---
const ICONS = {
  bell:'<svg viewBox="0 0 24 24"><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg>',
  lock:'<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  "lock-big":'<svg viewBox="0 0 24 24"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/><circle cx="12" cy="16" r="1.4"/></svg>',
  check:'<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>',
  shield:'<svg viewBox="0 0 24 24"><path d="M12 3 20 6v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/></svg>',
  activity:'<svg viewBox="0 0 24 24"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>',
  gear:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.2"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 1h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6A7 7 0 0 0 5 12a7 7 0 0 0 .1 1.2l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 23h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6A7 7 0 0 0 19 12z"/></svg>',
  min:'<svg viewBox="0 0 24 24"><path d="M5 12h14"/></svg>',
  max:'<svg viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="1.5"/></svg>',
  close:'<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg>',
  grid:'<svg viewBox="0 0 24 24"><rect x="4" y="4" width="7" height="7" rx="1"/><rect x="13" y="4" width="7" height="7" rx="1"/><rect x="4" y="13" width="7" height="7" rx="1"/><rect x="13" y="13" width="7" height="7" rx="1"/></svg>',
  search:'<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
  file:'<svg viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>',
  share:'<svg viewBox="0 0 24 24"><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 11 16 7M8.2 13l7.8 4"/></svg>',
  box:'<svg viewBox="0 0 24 24"><path d="M12 3 20 7v10l-8 4-8-4V7z"/><path d="M4 7l8 4 8-4M12 11v10"/></svg>',
  wave:'<svg viewBox="0 0 24 24"><path d="M3 12c2 0 2-5 4-5s2 10 4 10 2-10 4-10 2 5 4 5"/></svg>',
  globe:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
  doc:'<svg viewBox="0 0 24 24"><path d="M7 3h7l5 5v13H7z"/><path d="M9 12h6M9 16h6"/></svg>',
  bolt:'<svg viewBox="0 0 24 24"><path d="M13 2 4 14h6l-1 8 9-12h-6z"/></svg>',
  arrow:'<svg viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  down:'<svg viewBox="0 0 24 24"><path d="M12 5v14M6 13l6 6 6-6"/></svg>',
  "cloud-off":'<svg viewBox="0 0 24 24"><path d="M7 18a4 4 0 0 1-.5-8 6 6 0 0 1 10-2M3 3l18 18"/></svg>',
  cpu:'<svg viewBox="0 0 24 24"><rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2"/></svg>',
  zap:'<svg viewBox="0 0 24 24"><path d="M13 2 4 14h6l-1 8 9-12h-6z"/></svg>',
  bug:'<svg viewBox="0 0 24 24"><rect x="8" y="8" width="8" height="10" rx="4"/><path d="M9 6l1 2M15 6l-1 2M5 11h3M16 11h3M5 16h3M16 16h3M12 18v3"/></svg>',
  database:'<svg viewBox="0 0 24 24"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3 3 7 3s7-1.3 7-3V6"/></svg>',
  alert:'<svg viewBox="0 0 24 24"><path d="M12 4 3 19h18z"/><path d="M12 10v4M12 17h.01"/></svg>',
  rss:'<svg viewBox="0 0 24 24"><path d="M5 19a2 2 0 1 0 .01 0M5 13a6 6 0 0 1 6 6M5 7a12 12 0 0 1 12 12"/></svg>',
  code:'<svg viewBox="0 0 24 24"><path d="m9 8-5 4 5 4M15 8l5 4-5 4"/></svg>',
  cube:'<svg viewBox="0 0 24 24"><path d="M12 3 20 7v10l-8 4-8-4V7z"/><path d="M4 7l8 4 8-4"/></svg>',
  brain:'<svg viewBox="0 0 24 24"><path d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-1 5 3 3 0 0 0 2 4 3 3 0 0 0 5 1V5a3 3 0 0 0-3-1zM15 4a3 3 0 0 1 3 3 3 3 0 0 1 1 5 3 3 0 0 1-2 4 3 3 0 0 1-5 1"/></svg>',
  target:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1"/></svg>',
  key:'<svg viewBox="0 0 24 24"><circle cx="8" cy="8" r="4"/><path d="M11 11l8 8M16 16l2-2M18 18l2-2"/></svg>',
  eye:'<svg viewBox="0 0 24 24"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="2.5"/></svg>',
  fingerprint:'<svg viewBox="0 0 24 24"><path d="M5 11a7 7 0 0 1 13-3M6 15a10 10 0 0 0 1 4M12 11v3a6 6 0 0 0 2 4M9 19a8 8 0 0 1-1-6 4 4 0 0 1 8 0"/></svg>',
  refresh:'<svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 0 0-14-4M4 6v4h4M4 13a8 8 0 0 0 14 4M20 18v-4h-4"/></svg>',
  wifi:'<svg viewBox="0 0 24 24"><path d="M2 8a16 16 0 0 1 20 0M5 12a11 11 0 0 1 14 0M8.5 15.5a6 6 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/></svg>',
  menu:'<svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg>',
};
function paintIcons(root=document){root.querySelectorAll('i[data-ic]').forEach(el=>{const k=el.getAttribute('data-ic');if(ICONS[k])el.innerHTML=ICONS[k];});}

// --- Sample data that mirrors the reference dashboard (fallback when not in Tauri) ---
const SAMPLE = {
  stats:[
    {ic:'shield',v:'1,248',l:'Threats Blocked',n:'+185 last 7 days',up:true},
    {ic:'file',v:'2.67M',l:'Files Scanned',n:'+231k last 7 days',up:true},
    {ic:'code',v:'9,842',l:'YARA Rules Loaded',n:'Updated 2h ago'},
    {ic:'lock',v:'312',l:'Quarantined Items',n:'Total items isolated'},
    {ic:'alert',v:'86',l:'Behavioral Alerts',n:'+14 last 7 days',up:true},
    {ic:'rss',v:'Up to date',l:'Intel Feed Status',n:'Feeds healthy'},
  ],
  modules:[
    {ic:'database',t:'Hash + Bloom Filter',s:'Fast hash lookup & memory efficiency'},
    {ic:'code',t:'YARA-X Rules',s:'Advanced pattern matching engine'},
    {ic:'cube',t:'PE / ELF / Mach-O',s:'Binary parsing & structure analysis'},
    {ic:'doc',t:'PDF / Office / Script',s:'Document & script inspection'},
    {ic:'target',t:'Static Heuristics',s:'AI-driven static code analysis'},
    {ic:'share',t:'Behavioral + Graph',s:'Process, file & network correlation'},
    {ic:'box',t:'Sandbox Emulation',s:'Multi-OS dynamic analysis'},
    {ic:'brain',t:'ML / Anomaly Detection',s:'Unsupervised anomaly scoring'},
    {ic:'lock',t:'Encrypted Quarantine',s:'AES-256 encrypted vault'},
    {ic:'rss',t:'Threat Intel Feed',s:'Signed feeds & hot-reload'},
  ],
  detections:[
    {time:'10:42:18',item:'invoice_helper.exe',type:'File',risk:'malicious',action:'Quarantined'},
    {time:'10:31:45',item:'api-client.dll',type:'File',risk:'suspicious',action:'Blocked'},
    {time:'10:20:09',item:'update_service.sh',type:'File',risk:'suspicious',action:'Quarantined'},
    {time:'10:15:32',item:'report.docx',type:'File',risk:'clean',action:'Allowed'},
    {time:'10:07:51',item:'chrome.exe',type:'Process',risk:'clean',action:'Allowed'},
  ],
  graph:{
    nodes:[
      {id:'c',label:'this host',pid:'5 live connection(s)',x:50,y:50,kind:'center'},
      {id:'e0',label:'140.82.121.4:443',pid:'ESTABLISHED',x:50,y:10,kind:'net'},
      {id:'e1',label:'93.184.216.34:443',pid:'ESTABLISHED',x:86,y:34,kind:'net'},
      {id:'e2',label:'185.220.101.4:9001',pid:'⚠ port 9001 · Tor',x:80,y:78,kind:'malicious'},
      {id:'e3',label:'45.137.21.9:4444',pid:'⚠ port 4444 · Metasploit',x:20,y:78,kind:'malicious'},
      {id:'e4',label:'151.101.0.133:443',pid:'ESTABLISHED',x:14,y:34,kind:'net'},
    ],
    edges:[['c','e0'],['c','e1'],['c','e2'],['c','e3'],['c','e4']],
  },
  mitre:[
    {ic:'key',name:'Initial Access',tech:['T1566','T1190']},
    {ic:'zap',name:'Execution',tech:['T1059','T1204']},
    {ic:'refresh',name:'Persistence',tech:['T1547','T1060']},
    {ic:'eye',name:'Defense Evasion',tech:['T1027','T1036']},
    {ic:'search',name:'Discovery',tech:['T1082','T1018']},
  ],
  chart:{
    baseline:[18,20,19,22,24,23,26,30,34,40,46,52,58,55,50,46,44,48,52,49,44,38,30,24],
    actual:[16,19,22,20,28,24,33,52,40,70,55,88,62,95,58,72,50,84,60,46,52,40,30,26],
    xlabels:['12 AM','6 AM','12 PM','6 PM','12 AM'],
  },
  feed:[
    {ic:'wifi',g:true,name:'Feeds Status',val:'All systems operational',ok:true},
    {ic:'database',name:'Signature DB',val:'v2026.06.20.1142'},
    {ic:'code',name:'YARA Rules',val:'9,842 rules loaded'},
    {ic:'refresh',name:'Hot Reload',val:'Enabled'},
  ],
  system:{os:'Windows 11 Pro 23H2 (x64)',cpu:'6%',ram:'28%',disk:'12%',net:'2.3 KB/s'},
  live:{processes:312,connections:268,flagged_ports:2,aegis:true},
};

// --- Tauri bridge: use the real engine when running inside the app ---
const TAURI = !!(window.__TAURI__ && window.__TAURI__.core);
async function invoke(cmd,args){ if(!TAURI) return null; try{ return await window.__TAURI__.core.invoke(cmd,args);}catch(e){console.warn(cmd,e);return null;} }

// --- Renderers ---
function renderStats(d){
  document.getElementById('stats').innerHTML = d.map(s=>`
    <div class="stat">
      <div class="si"><i data-ic="${s.ic}"></i></div>
      <div class="sv">${s.v}</div>
      <div class="sl">${s.l}</div>
      <div class="sn ${s.up?'up':''}">${s.up?'▲ ':''}${s.n}</div>
    </div>`).join('');
}
function renderModules(d){
  document.getElementById('modules').innerHTML = d.map(m=>{
    const off = m.active===false;
    const badge = off
      ? `<div class="badge badge-off">OFF</div>`
      : `<div class="badge"><span class="dot"></span>ACTIVE</div>`;
    return `<div class="module${off?' module-off':''}">
      ${badge}
      <div class="mi"><i data-ic="${m.ic}"></i></div>
      <div class="mt">${m.t}</div>
      <div class="ms">${m.s}</div>
    </div>`;
  }).join('');
}
function renderDetections(d){
  document.getElementById('detections').innerHTML = d.map(r=>`
    <tr>
      <td>${r.time}</td>
      <td class="item">${r.item}</td>
      <td>${r.type}</td>
      <td><span class="tag ${r.risk}">${r.risk[0].toUpperCase()+r.risk.slice(1)}</span></td>
      <td>${r.action}</td>
    </tr>`).join('');
}
function renderGraph(g){
  const area = document.getElementById('graph');
  const byId = Object.fromEntries(g.nodes.map(n=>[n.id,n]));
  if(!g.nodes.length){ area.innerHTML='<div class="empty">No live connections observed</div>'; return; }
  const lines = g.edges.map(([a,b])=>{
    const A=byId[a],B=byId[b];
    const bad = (A&&A.kind==='malicious')||(B&&B.kind==='malicious');
    const stroke = bad ? 'rgba(239,83,80,.7)' : 'rgba(39,216,238,.35)';
    return `<line x1="${A.x}" y1="${A.y}" x2="${B.x}" y2="${B.y}" stroke="${stroke}" stroke-width="${bad?0.6:0.4}"/>`;
  }).join('');
  const svg = `<svg class="gline" viewBox="0 0 100 100" preserveAspectRatio="none">${lines}</svg>`;
  const icon = k => k==='malicious'?'alert':(k==='net'?'globe':(k==='file'?'file':'cpu'));
  const nodes = g.nodes.map(n=>`
    <div class="gnode ${n.kind}" style="left:${n.x}%;top:${n.y}%" title="${n.label} - ${n.pid||''}">
      <div class="gdot"><i data-ic="${icon(n.kind)}"></i></div>
      <div class="glabel">${n.label}</div>
      <div class="gpid">${n.pid||''}</div>
    </div>`).join('');
  area.innerHTML = svg + nodes;
}
function renderMitre(d){
  document.getElementById('mitre').innerHTML = d.map(m=>`
    <li>
      <span class="mitre-ic"><i data-ic="${m.ic}"></i></span>
      <span class="mitre-name">${m.name}</span>
      ${m.tech.map(t=>`<span class="tech">${t}</span>`).join('')}
    </li>`).join('');
}
function renderChart(c){
  const W=300,H=150,pad=6;
  const max=Math.max(...c.actual,...c.baseline)*1.1;
  const xs=i=>pad+(i*(W-2*pad)/(c.actual.length-1));
  const ys=v=>H-pad-(v/max)*(H-2*pad);
  const path=a=>a.map((v,i)=>`${i?'L':'M'}${xs(i).toFixed(1)} ${ys(v).toFixed(1)}`).join(' ');
  const area=`M${xs(0)} ${ys(c.actual[0])} `+c.actual.map((v,i)=>`L${xs(i).toFixed(1)} ${ys(v).toFixed(1)}`).join(' ')+` L${xs(c.actual.length-1)} ${H-pad} L${xs(0)} ${H-pad} Z`;
  document.getElementById('chart').innerHTML=`
    <svg viewBox="0 0 ${W} ${H}" width="100%" height="100%" preserveAspectRatio="none">
      <defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="rgba(52,224,138,.30)"/><stop offset="1" stop-color="rgba(52,224,138,0)"/></linearGradient></defs>
      <path d="${area}" fill="url(#ag)"/>
      <path d="${path(c.baseline)}" fill="none" stroke="#27d8ee" stroke-width="1.4" stroke-dasharray="4 3" opacity=".8"/>
      <path d="${path(c.actual)}" fill="none" stroke="#34e08a" stroke-width="1.8"/>
    </svg>`;
}
function renderFeed(d){
  document.getElementById('feed').innerHTML = d.map(f=>`
    <li>
      <span class="feed-ic ${f.g?'g':''}"><i data-ic="${f.ic}"></i></span>
      <span class="feed-name">${f.name}</span>
      <span class="feed-val ${f.ok?'ok':''}">${f.val}</span>
    </li>`).join('');
}
function renderSystem(s){
  document.getElementById('sysstats').innerHTML =
    `System: <b>${s.os}</b><span>CPU: <b>${s.cpu}</b></span><span>RAM: <b>${s.ram}</b></span><span>Disk: <b>${s.disk}</b></span><span>Network: <b>${s.net}</b></span>`;
}
function renderSystemHealth(d){
  const el=document.getElementById('syshealth'); if(!el) return;
  const s=d.system||{}, live=d.live||{};
  const pct=v=>{const n=parseInt(String(v).replace('%',''));return isNaN(n)?0:n;};
  const gauge=(label,val)=>{const p=pct(val);return `<div class="gauge"><div class="gauge-top"><span>${label}</span><b>${val||'-'}</b></div><div class="gauge-bar"><div class="gauge-fill ${p>=85?'warn':''}" style="width:${p}%"></div></div></div>`;};
  const aegis = live.aegis ? '<span style="color:var(--green)">●</span>' : '<span style="color:var(--faint)">○</span>';
  el.innerHTML =
    gauge('CPU', s.cpu) + gauge('Memory', s.ram) + gauge('Disk', s.disk) +
    `<div class="sh-grid">
       <div class="sh-cell"><div class="v">${live.processes??'-'}</div><div class="l">Processes</div></div>
       <div class="sh-cell"><div class="v">${live.connections??'-'}</div><div class="l">Connections</div></div>
       <div class="sh-cell"><div class="v" style="color:${live.flagged_ports>0?'var(--red)':'var(--green)'}">${live.flagged_ports??0}</div><div class="l">Flagged Ports</div></div>
       <div class="sh-cell"><div class="v">${aegis}</div><div class="l">Aegis-50M</div></div>
     </div>
     <div class="page-sub" style="margin-top:11px">${s.os||''} · Net ${s.net||'-'}</div>`;
}

// Render the whole dashboard from a data object (live or sample).
function renderAll(d){
  renderStats(d.stats); renderModules(d.modules); renderDetections(d.detections);
  renderGraph(d.graph); renderMitre(d.mitre); renderChart(d.chart);
  renderFeed(d.feed); renderSystem(d.system); renderSystemHealth(d); paintIcons();
  // Real "last full scan" + "definitions age" from the engine (no more fakes).
  const ls=document.getElementById('lastScan'); if(ls&&d.last_scan) ls.textContent=d.last_scan;
  const da=document.getElementById('defsAge'); if(da&&d.defs_age) da.textContent=d.defs_age;
  // Live network summary in its own status-bar element (so the 2s metrics
  // tick, which rewrites the system stats, doesn't clobber it).
  if(d.live){
    const el=document.getElementById('sb-ports');
    if(el && d.live.connections!=null){
      const aegis = d.live.aegis
        ? `<span style="color:var(--green)">Aegis-50M ●</span>`
        : `<span style="color:var(--faint)">Aegis-50M ○</span>`;
      el.innerHTML = aegis + `&nbsp;&nbsp;Conns: <b>${d.live.connections}</b>  `
        + (d.live.flagged_ports>0
            ? `<span style="color:var(--red);font-weight:700">⚠ ${d.live.flagged_ports} malicious port(s)</span>`
            : `<span style="color:var(--green)">● ports clean</span>`);
    }
    // edge-triggered in-app alert when new malicious-port activity appears
    const fp = d.live.flagged_ports||0;
    if(fp > (window.__prevFlagged||0)) toast('⚠ '+fp+' connection(s) on malware-associated ports','alert');
    window.__prevFlagged = fp;
  }
}

// --- Wiring ---
let LAST = SAMPLE;
async function refresh(){
  const data = (await invoke('dashboard_data')) || SAMPLE;
  LAST = data;
  renderAll(data);
}

// ---------- Router / pages ----------
const cap = s => s ? s[0].toUpperCase()+s.slice(1) : s;
function threatTable(rows, cols){
  if(!rows || !rows.length) return '<div class="empty">No threats found - everything clean ✓</div>';
  return `<table class="bigtable"><thead><tr>${cols.map(c=>`<th>${c}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table>`;
}
const PAGES = {
  scan: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="search"></i>Scan Center</div>
      <div class="page-sub">Scan a file or folder with the full engine: hash, YARA-X, parsers, heuristics, static-ML & plugins.</div></div></div>
    <div class="panel"><div class="toolbar">
      <input class="input" id="scanPath" placeholder="/path/to/scan" value="."/>
      <button class="btn inline" id="scanBrowse"><i data-ic="file"></i> Browse…</button>
      <button class="btn btn-primary inline" id="scanGo"><i data-ic="bolt"></i> Scan</button>
    </div><div id="scanOut" style="margin-top:14px"><div class="empty">Choose a path and press Scan.</div></div></div>`,
  realtime: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="shield"></i>Real-Time Protection</div>
      <div class="page-sub">Hashes the executables of running processes and checks them against the engine in real time.</div></div>
      <button class="btn btn-primary inline" id="rtGo"><i data-ic="activity"></i> Scan Running Processes</button></div>
    <div class="panel"><div id="rtOut"><div class="empty">Press “Scan Running Processes” to inspect live processes.</div></div></div>`,
  sentinel: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="fingerprint"></i>Process Sentinel</div>
      <div class="page-sub">Detects NEW/unknown apps running (identified by hash, not name) and HIDDEN processes (cross-view anti-rootkit). Learn a baseline on a clean system, then watch for anything new.</div></div>
      <div><button class="btn inline" id="senLearn"><i data-ic="check"></i> Learn Baseline</button>
      <button class="btn btn-primary inline" id="senScan"><i data-ic="fingerprint"></i> Scan Now</button></div></div>
    <div class="kpis" id="senKpis"></div>
    <div class="panel"><div class="panel-h">NEW / UNKNOWN EXECUTABLES</div><div id="senNew" style="margin-top:8px"><div class="empty">Press “Scan Now”.</div></div></div>
    <div class="panel"><div class="panel-h">HIDDEN PROCESSES <span class="muted">(rootkit cross-view)</span></div><div id="senHidden" style="margin-top:8px"></div></div>
    <div class="panel"><div class="panel-h">STEALTH INDICATORS</div><div id="senStealth" style="margin-top:8px"></div></div>
    <div class="panel"><div class="panel-h-row"><span class="panel-h">LIVE EXEC MONITOR <span class="muted">(kernel cn_proc)</span></span>
      <button class="btn inline" id="senLiveStart"><i data-ic="activity"></i> Start Live Monitor</button></div>
      <div class="page-sub" style="margin:6px 0">Streams every process the moment the kernel reports it (resists userland hiding). Needs root.</div>
      <div id="senLive"><div class="empty">Not started.</div></div></div>`,
  shields: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="shield"></i>Network & Theft Shield</div>
      <div class="page-sub">Threat-intel firewall, private web/phishing blocking, and crypto/credential theft defense - all driven by our signed intelligence.</div></div>
      <button class="btn inline" id="shReload"><i data-ic="refresh"></i> Refresh</button></div>
    <div class="kpis" id="shKpis"></div>
    <div class="panel"><div class="panel-h-row"><span class="panel-h">SMART FIREWALL</span>
      <button class="btn btn-primary inline" id="fwApply"><i data-ic="shield"></i> Apply firewall rules</button></div>
      <div class="page-sub" style="margin:6px 0">Blocks connections to malicious IPs and RAT/C2 ports via your OS native firewall (nftables / netsh / pf). Needs admin/root.</div>
      <div id="fwInfo" class="muted"></div></div>
    <div class="panel"><div class="panel-h-row"><span class="panel-h">WEB / PHISHING PROTECTION</span>
      <button class="btn btn-primary inline" id="webApply"><i data-ic="globe"></i> Block malicious domains</button></div>
      <div class="page-sub" style="margin:6px 0">Sinkholes phishing/malware domains locally in the OS hosts file - no cloud, fully private. Needs admin/root.</div>
      <div id="webInfo" class="muted"></div></div>
    <div class="panel"><div class="panel-h-row"><span class="panel-h">STEALER & WALLET SHIELD</span>
      <button class="btn btn-primary inline" id="stArm"><i data-ic="fingerprint"></i> Arm decoys</button></div>
      <div class="page-sub" style="margin:6px 0">Plants decoy wallet/credential files; any process that reads one is an infostealer. For live blocking run <code>aether stealerguard &lt;dir&gt; --watch --kill</code> (root).</div>
      <div id="stInfo" class="muted"></div></div>
    <div class="panel"><div class="panel-h">CLIPBOARD GUARD <span class="muted">(crypto clippers)</span></div>
      <ul class="feature-list" style="margin-top:10px">
        <li><i data-ic="check"></i>Detects when a copied wallet address is swapped by a clipboard hijacker</li>
        <li><i data-ic="check"></i>Run <code>aether clipguard --watch --restore</code> to monitor and auto-restore the original address</li>
      </ul></div>`,
  network: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="wifi"></i>Network Monitor</div>
      <div class="page-sub">Live TCP connections checked against a database of malware/RAT/C2 ports. Flags use of known-malicious ports.</div></div>
      <button class="btn inline" id="netReload"><i data-ic="refresh"></i> Refresh</button></div>
    <div class="kpis" id="netKpis"></div>
    <div class="panel"><div class="panel-h">FLAGGED CONNECTIONS</div>
      <div class="page-sub" style="margin:6px 0 4px">Correlated against malicious ports, known-bad intel IPs and reverse-DNS domains.</div>
      <div id="netFlagged" style="margin-top:6px"></div></div>
    <div class="panel"><div class="panel-h">OUTBOUND DNS MONITOR</div>
      <ul class="feature-list" style="margin-top:10px">
        <li><i data-ic="check"></i><span id="dnsDomains">Domain IOCs loaded</span> - lookups of these are flagged before a connection is made</li>
        <li><i data-ic="check"></i>Enable live capture: <code>cargo build -p aether-cli --features pcap</code> then <code>sudo aether dnswatch</code> (needs libpcap + CAP_NET_RAW)</li>
      </ul></div>
    <div class="panel"><div class="panel-h">ACTIVE CONNECTIONS</div><div id="netConns" style="margin-top:10px"></div></div>`,
  quarantine: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="lock"></i>Quarantine Vault</div>
      <div class="page-sub">ChaCha20-Poly1305 encrypted. Restore or permanently delete isolated samples.</div></div>
      <button class="btn inline" id="qReload"><i data-ic="refresh"></i> Reload</button></div>
    <div class="panel"><div id="qOut"><div class="empty">Loading vault…</div></div></div>`,
  intel: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="globe"></i>Threat Intel</div>
      <div class="page-sub">Free abuse.ch feeds (ThreatFox + MalwareBazaar). Hashes & IOCs only - never malware binaries.</div></div>
      <button class="btn btn-primary inline" id="intelGo"><i data-ic="down"></i> Update Now</button></div>
    <div class="kpis" id="intelKpis"></div>
    <div class="panel"><div class="panel-h">FEED SOURCES</div><ul class="feature-list" style="margin-top:10px">
      <li><i data-ic="check"></i><b>ThreatFox</b> - IOCs (sha256/md5/domain/ip/url) tagged by malware family</li>
      <li><i data-ic="check"></i><b>MalwareBazaar</b> - recent malware SHA-256 hashes</li>
      <li><i data-ic="check"></i>HMAC-signed delta updates, hot-reloaded into the signature DB without restart</li>
    </ul></div>`,
  signatures: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="file"></i>Signatures</div>
      <div class="page-sub">Exact-match hash database (Bloom-filtered) + compiled YARA-X rules.</div></div>
      <button class="btn btn-primary inline" id="intelGo"><i data-ic="down"></i> Update Signatures</button></div>
    <div class="kpis" id="intelKpis"></div>`,
  reports: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="doc"></i>Reports</div>
      <div class="page-sub">Every scan (manual, scheduled and USB) is logged locally. Export the history for your records.</div></div>
      <div style="display:flex;gap:8px"><button class="btn inline" id="rpJson"><i data-ic="down"></i> JSON</button>
        <button class="btn inline" id="rpCsv"><i data-ic="down"></i> CSV</button>
        <button class="btn inline" id="rpHtml"><i data-ic="down"></i> HTML</button>
        <button class="btn inline" id="rpClear">Clear</button></div></div>
    <div class="kpis" id="rpKpis"></div>
    <div class="panel"><div class="panel-h">SCAN HISTORY</div><div id="rpOut" style="margin-top:10px"><div class="empty">Loading…</div></div></div>`,
  behavior: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="share"></i>Behavior + Graph Engine</div>
      <div class="page-sub">Process/file/network graph with MITRE ATT&CK rules (injection, ransomware, LOLBin chains, C2, persistence).</div></div>
      <button class="btn btn-primary inline" id="rtGo"><i data-ic="activity"></i> Analyze Live Processes</button></div>
    <div class="panel"><div class="panel-h">ANALYZE AN EVENT TRACE</div>
      <div class="page-sub" style="margin:6px 0">Score a recorded process/file/network trace (JSON) against the MITRE rule set. Try the bundled samples in <code>assets/traces</code>.</div>
      <div class="toolbar" style="margin-top:10px">
        <input class="input" id="bhPath" placeholder="/path/to/trace.json"/>
        <button class="btn inline" id="bhBrowse"><i data-ic="file"></i> Choose trace…</button>
        <button class="btn btn-primary inline" id="bhGo"><i data-ic="bolt"></i> Analyze</button>
      </div><div id="bhOut" style="margin-top:12px"></div></div>
    <div class="panel"><div class="panel-h">LIVE PROCESS TELEMETRY</div><div id="rtOut" style="margin-top:10px"><div class="empty">Press “Analyze Live Processes”.</div></div></div>`,
  sandbox: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="box"></i>Dynamic Sandbox & Emulation</div>
      <div class="page-sub">Static iced-x86 sweep + exploit-staging detection. Choose a file (shellcode, binary or document) to emulate and analyze for anti-evasion / shellcode tells.</div></div></div>
    <div class="panel"><div class="toolbar">
      <input class="input" id="sbPath" placeholder="/path/to/sample"/>
      <button class="btn inline" id="sbBrowse"><i data-ic="file"></i> Choose file…</button>
      <button class="btn btn-primary inline" id="sbGo"><i data-ic="bolt"></i> Emulate</button>
    </div><div id="sbOut" style="margin-top:14px"><div class="empty">Choose a file and press Emulate.</div></div></div>`,
  anomaly: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="wave"></i>Anomaly Detection</div>
      <div class="page-sub">Per-host behavioral baseline with online learning. Learn from benign event traces, then score new traces for never-seen programs, odd lineages and novel network destinations.</div></div></div>
    <div class="panel"><div class="toolbar">
      <input class="input" id="anPath" placeholder="/path/to/trace.json"/>
      <button class="btn inline" id="anBrowse"><i data-ic="file"></i> Choose trace…</button>
      <button class="btn inline" id="anLearn"><i data-ic="check"></i> Learn baseline</button>
      <button class="btn btn-primary inline" id="anScore"><i data-ic="bolt"></i> Score</button>
    </div><div id="anOut" style="margin-top:14px"><div class="empty">Pick an event-trace JSON (see assets/traces), then Learn or Score.</div></div></div>`,
  settings: ()=>`
    <div class="page-head"><div><div class="page-title"><i data-ic="gear"></i>Settings</div>
      <div class="page-sub">Toggle detection engines and paths. Changes hot-reload the engine - no restart.</div></div></div>
    <div class="panel"><div class="panel-h">DETECTION ENGINES</div>
      <div id="settingsForm" style="margin-top:12px"><div class="empty">Loading settings…</div></div></div>
    <div class="panel"><div class="panel-h">SIGNATURE UPDATES</div>
      <div id="updStatus" class="page-sub" style="margin:10px 0">Checking…</div>
      <div class="setting"><span><b>Signed feed URL</b><br><span class="muted">Ed25519-signed; verified + rollback-protected before applying</span></span>
        <span style="display:flex;gap:8px;flex:1;max-width:480px"><input class="input" id="updUrl" placeholder="https://feeds.example.com/aether.json"/><button class="btn inline" id="updSaveUrl">Save</button></span></div>
      <div style="margin-top:12px"><button class="btn btn-primary inline" id="updNow"><i data-ic="down"></i> Update Now</button></div></div>
    <div class="panel"><div class="panel-h">SCHEDULED & AUTOMATIC SCANS</div>
      <div class="setting"><span><b>Scheduled scan</b><br><span class="muted">Run a full scan automatically on a cadence</span></span>
        <select class="input" id="schCadence" style="max-width:170px">
          <option value="off">Off</option><option value="hourly">Hourly</option>
          <option value="daily">Daily</option><option value="weekly">Weekly</option></select></div>
      <div class="setting"><span><b>Scan folder</b><br><span class="muted">Blank = your home directory</span></span>
        <span style="display:flex;gap:8px;flex:1;max-width:420px"><input class="input" id="schPath" placeholder="(home directory)"/><button class="btn inline" id="schBrowse">Browse…</button></span></div>
      <label class="setting"><input type="checkbox" id="schUsb"/><span><b>Auto-scan USB / removable media</b><br><span class="muted">Scan drives automatically the moment they are plugged in</span></span></label>
      <div style="margin-top:12px"><button class="btn btn-primary inline" id="schSave"><i data-ic="check"></i> Save schedule</button></div></div>
    <div class="panel"><div class="panel-h">ABOUT</div><ul class="feature-list" style="margin-top:10px">
      <li><i data-ic="check"></i>Local-first · everything runs offline; cloud intel is opt-in</li>
      <li><i data-ic="check"></i>AetherAV desktop ${window.__APPVER||'v2026.1.0'} · Tauri v2 · cross-platform</li>
    </ul></div>`,
};
function capabilityPage(ic,title,sub,items){
  return `<div class="page-head"><div><div class="page-title"><i data-ic="${ic}"></i>${title}</div>
    <div class="page-sub">${sub}</div></div><span class="module"><span class="badge"><span class="dot"></span>ACTIVE</span></span></div>
    <div class="panel"><div class="panel-h">DETECTION CAPABILITIES</div>
    <ul class="feature-list" style="margin-top:10px">${items.map(i=>`<li><i data-ic="check"></i>${i}</li>`).join('')}</ul></div>`;
}
function intelKpis(){
  const find=l=>(LAST.stats||[]).find(s=>s.l===l)?.v||'0';
  return [['Malware Signatures',find('Malware Signatures')],['Threat Intel IOCs',find('Threat Intel IOCs')],
          ['YARA Rules Loaded',find('YARA Rules Loaded')]]
    .map(([l,v])=>`<div class="stat"><div class="sv">${v}</div><div class="sl">${l}</div></div>`).join('');
}
function bindPage(name, host){
  const upd = host.querySelector('#intelGo');
  if(upd) upd.onclick=async()=>{ if(!TAURI){toast('Run inside the app to download feeds');return;} toast('Downloading threat-intel feeds…'); const r=await invoke('update_intel'); if(r&&r.message)toast(r.message); await refresh(); const k=host.querySelector('#intelKpis'); if(k)k.innerHTML=intelKpis(); };
  const k=host.querySelector('#intelKpis'); if(k)k.innerHTML=intelKpis();

  if(name==='scan'){
    const go=async(p)=>{ const out=host.querySelector('#scanOut'); out.innerHTML='<div class="scanning"><span class="dot"></span> Scanning…</div>';
      const r=await invoke('scan_path_cmd',{path:p}); if(!r){out.innerHTML='<div class="empty">Run inside the app to scan.</div>';return;}
      if(r.error){out.innerHTML=`<div class="empty">${r.error}</div>`;return;}
      const rows=r.threats.map(t=>`<tr><td class="mono">${t.path}</td><td><span class="tag ${t.risk}">${cap(t.risk)}</span></td><td>${t.signature}</td><td>${t.detail||''}</td><td><button class="rowbtn danger" data-q="${encodeURIComponent(t.path)}" data-sig="${encodeURIComponent(t.signature||'')}">Quarantine</button></td></tr>`).join('');
      out.innerHTML=`<div class="page-sub" style="margin-bottom:10px">Scanned <b>${r.summary.scanned}</b> · malicious <b style="color:var(--red)">${r.summary.malicious}</b> · suspicious <b style="color:var(--amber)">${r.summary.suspicious}</b> · ${r.summary.ms} ms</div>`+threatTable(rows,['Path','Risk','Signature','Detail','Action']);
      out.querySelectorAll('[data-q]').forEach(b=>b.onclick=async()=>{ b.disabled=true; const r2=await invoke('quarantine_add',{path:decodeURIComponent(b.dataset.q),threat:decodeURIComponent(b.dataset.sig)}); if(r2&&r2.message) toast(r2.message, r2.ok?'success':'alert'); if(r2&&r2.ok){ b.textContent='Quarantined'; } else { b.disabled=false; } }); };
    host.querySelector('#scanGo').onclick=()=>go(host.querySelector('#scanPath').value||'.');
    host.querySelector('#scanBrowse').onclick=async()=>{
      const p=await invoke('pick_folder');
      if(p) host.querySelector('#scanPath').value=p;
    };
  }
  if(name==='settings'){
    const wrap=host.querySelector('#settingsForm');
    invoke('get_settings').then(s=>{
      s=s||{heuristics:true,ml:true,yara:true,sandbox:true,intel:true,plugins:false,quarantine_dir:'',auto_update_hours:6};
      const tog=(key,label,desc)=>`<label class="setting"><input type="checkbox" data-set="${key}" ${s[key]?'checked':''}/><span><b>${label}</b><br><span class="muted">${desc}</span></span></label>`;
      wrap.innerHTML=`
        ${tog('heuristics','Static heuristics','Explainable PE/ELF/PDF/script scoring')}
        ${tog('ml','Static ML classifier','Logistic model over PE features')}
        ${tog('yara','YARA-X rules','Pattern-matching engine')}
        ${tog('sandbox','Sandbox / emulation','Anti-evasion + shellcode analysis')}
        ${tog('intel','Threat-intel IOC matching','URLs/IPs/domains in content')}
        ${tog('plugins','Third-party plugins','Subprocess detectors')}
        <div class="setting"><span><b>Quarantine directory</b><br><span class="muted">Encrypted vault location (blank = default)</span></span>
          <span style="display:flex;gap:8px;flex:1;max-width:420px"><input class="input" id="setQDir" value="${s.quarantine_dir||''}" placeholder="(default)"/><button class="btn inline" id="setQBrowse">Browse…</button></span></div>
        <div style="margin-top:14px"><button class="btn btn-primary inline" id="setSave"><i data-ic="check"></i> Save &amp; Reload Engines</button></div>`;
      paintIcons(wrap);
      host.querySelector('#setQBrowse').onclick=async()=>{const p=await invoke('pick_folder'); if(p) host.querySelector('#setQDir').value=p;};
      host.querySelector('#setSave').onclick=async()=>{
        const out={...s};
        wrap.querySelectorAll('[data-set]').forEach(c=>out[c.dataset.set]=c.checked);
        out.quarantine_dir=host.querySelector('#setQDir').value;
        const r=await invoke('set_settings',{settings:out});
        if(r&&r.message) toast(r.message);
        refresh();
      };
      const uu=host.querySelector('#updUrl'); if(uu) uu.value=s.update_url||'';
      // Scheduled / USB auto-scan preferences.
      const sc=host.querySelector('#schCadence'); if(sc) sc.value=s.scan_schedule||'off';
      const sp=host.querySelector('#schPath'); if(sp) sp.value=s.scan_schedule_path||'';
      const sus=host.querySelector('#schUsb'); if(sus) sus.checked=!!s.usb_autoscan;
    });
    const schB=host.querySelector('#schBrowse'); if(schB) schB.onclick=async()=>{const p=await invoke('pick_folder'); if(p) host.querySelector('#schPath').value=p;};
    const schS=host.querySelector('#schSave'); if(schS) schS.onclick=async()=>{
      const r=await invoke('set_schedule',{schedule:host.querySelector('#schCadence').value,
        path:host.querySelector('#schPath').value, usb:host.querySelector('#schUsb').checked});
      if(r&&r.message) toast(r.message,'success');
    };
    // Signature-updates panel (manual "Update Now" + last-update status).
    const renderUpd=async()=>{
      const el=host.querySelector('#updStatus'); if(!el) return;
      const st=await invoke('update_status');
      if(!st){el.textContent='Run inside the app.';return;}
      const last = st.last_update ? new Date(st.last_update*1000).toLocaleString() : 'never';
      const url = st.url_set ? '<span style="color:var(--green)">URL set</span>'
                            : '<span style="color:var(--amber)">no URL configured</span>';
      el.innerHTML = `Last update: <b>${last}</b> &nbsp;·&nbsp; feed version <b>${st.version||0}</b> &nbsp;·&nbsp; ${url}`;
    };
    const su=host.querySelector('#updSaveUrl'); if(su) su.onclick=async()=>{
      const url=host.querySelector('#updUrl').value;
      const r=await invoke('set_update_url',{url}); if(r&&r.message) toast(r.message,'success'); renderUpd();
    };
    const un=host.querySelector('#updNow'); if(un) un.onclick=async()=>{
      un.disabled=true; toast('Checking for updates…');
      const r=await invoke('update_now');
      if(r&&r.message) toast(r.message, r.ok?'success':'alert');
      un.disabled=false; renderUpd(); refresh();
    };
    renderUpd();
  }
  if(name==='realtime' || name==='behavior'){
    const btn=host.querySelector('#rtGo');
    if(btn) btn.onclick=async()=>{ const out=host.querySelector('#rtOut'); out.innerHTML='<div class="scanning"><span class="dot"></span> Scanning running processes…</div>';
      const r=await invoke('scan_processes'); if(!r){out.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      const rows=(r.rows||[]).map(x=>`<tr><td>${x.pid}</td><td>${x.name}</td><td class="mono">${x.path}</td><td><span class="tag ${x.risk}">${cap(x.risk)}</span></td><td>${x.signature||''}</td></tr>`).join('');
      out.innerHTML=`<div class="page-sub" style="margin-bottom:10px">Scanned <b>${r.scanned}</b> processes · <b style="color:var(--amber)">${r.flagged}</b> flagged</div>`+threatTable(rows,['PID','Process','Image','Risk','Signature']); };
  }
  if(name==='sentinel'){
    const scan=async()=>{
      const k=host.querySelector('#senKpis'), nw=host.querySelector('#senNew'),
            hd=host.querySelector('#senHidden'), st=host.querySelector('#senStealth');
      nw.innerHTML='<div class="scanning"><span class="dot"></span> Enumerating processes + cross-view…</div>'; hd.innerHTML=''; st.innerHTML='';
      const r=await invoke('sentinel_scan'); if(!r){nw.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      const newR=r.new||[], hidden=r.hidden||[], stealth=r.stealth||[];
      const mal=newR.filter(x=>x.risk==='malicious'||x.risk==='suspicious').length;
      k.innerHTML=[['New/Unknown',newR.length],['Hidden',hidden.length],['Stealth',stealth.length],['Flagged',mal],['Baseline',r.learned?'set':'none']]
        .map(([l,v])=>`<div class="stat"><div class="sv">${v}</div><div class="sl">${l}</div></div>`).join('');
      if(!r.learned) nw.innerHTML='<div class="empty">No baseline yet - press “Learn Baseline” on a known-clean system first.</div>';
      else {
        const rows=newR.map(x=>`<tr><td>${x.pid}</td><td>${x.name}</td><td class="mono">${x.path}</td><td><span class="tag ${x.risk}">${cap(x.risk)}</span></td><td>${x.signature||''}</td></tr>`).join('');
        nw.innerHTML = rows ? threatTable(rows,['PID','Process','Image','Risk','Signature']) : '<div class="empty">Nothing new since the baseline ✓</div>';
      }
      hd.innerHTML = hidden.length ? `<div class="tag malicious">⚠ ${hidden.length} hidden PID(s): ${hidden.join(', ')}</div>` : '<div class="empty">No hidden processes (readdir vs kill agree) ✓</div>';
      const sr=stealth.map(x=>`<tr><td>${x.pid}</td><td>${x.name}</td><td class="mono">${x.path}</td><td>${x.why}</td></tr>`).join('');
      st.innerHTML = sr ? threatTable(sr,['PID','Process','Image','Why']) : '<div class="empty">No stealth indicators ✓</div>';
    };
    host.querySelector('#senScan').onclick=scan;
    host.querySelector('#senLearn').onclick=async()=>{
      const r=await invoke('sentinel_learn'); if(r&&r.message) toast(r.message,'success'); scan();
    };
    host.querySelector('#senLiveStart').onclick=async()=>{
      const r=await invoke('sentinel_watch'); if(r&&r.message) toast(r.message);
    };
    renderExecs(); // show any events already buffered
  }
  if(name==='shields'){
    const load=async()=>{
      const s=await invoke('shields_status')||{};
      const k=host.querySelector('#shKpis');
      if(k) k.innerHTML=[
        ['Firewall IPs',(s.firewall_ips||0).toLocaleString()],
        ['Malware ports',s.firewall_ports||0],
        ['Phishing domains',(s.web_domains||0).toLocaleString()],
        ['Platform',(s.platform||'-')],
      ].map(([l,v])=>`<div class="stat"><div class="sv">${v}</div><div class="sl">${l}</div></div>`).join('');
      const fi=host.querySelector('#fwInfo'); if(fi) fi.textContent=`Ready to block ${(s.firewall_ips||0).toLocaleString()} malicious IPs + ${s.firewall_ports||0} ports on ${s.platform||'this OS'}.`;
      const wi=host.querySelector('#webInfo'); if(wi) wi.textContent=`Ready to sinkhole ${(s.web_domains||0).toLocaleString()} malicious domains.`;
    };
    load();
    host.querySelector('#shReload').onclick=load;
    host.querySelector('#fwApply').onclick=async()=>{ const r=await invoke('firewall_apply'); if(r&&r.message) toast(r.message, r.ok?'success':'alert'); };
    host.querySelector('#webApply').onclick=async()=>{ const r=await invoke('webprotect_apply'); if(r&&r.message) toast(r.message, r.ok?'success':'alert'); };
    host.querySelector('#stArm').onclick=async()=>{ const r=await invoke('stealer_arm'); if(r&&r.message){ toast(r.message, r.ok?'success':'alert'); const si=host.querySelector('#stInfo'); if(si) si.textContent=r.message; } };
  }
  if(name==='network'){
    const load=async()=>{
      const k=host.querySelector('#netKpis'), fl=host.querySelector('#netFlagged'), co=host.querySelector('#netConns');
      fl.innerHTML='<div class="scanning"><span class="dot"></span> Reading sockets…</div>'; co.innerHTML='';
      const r=await invoke('network_status'); if(!r){fl.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      k.innerHTML=[['Connections',r.total],['Established',r.established],['Port DB',r.db_size],['Intel IPs',r.intel_ips||0],['Intel Domains',r.intel_domains||0],['Flagged',(r.flagged||[]).length]]
        .map(([l,v])=>`<div class="stat"><div class="sv">${v}</div><div class="sl">${l}</div></div>`).join('');
      const dd=host.querySelector('#dnsDomains'); if(dd) dd.textContent=`${r.intel_domains||0} domain IOCs loaded`;
      const fr=(r.flagged||[]).map(x=>`<tr><td class="mono">${x.local}</td><td class="mono">${x.remote}</td><td>${x.port}</td><td><span class="tag ${(x.severity==='high')?'malicious':'suspicious'}">${cap(x.severity)}</span></td><td>${x.reason||''}</td><td>${x.name}</td></tr>`).join('');
      fl.innerHTML = fr ? threatTable(fr,['Local','Remote','Port','Severity','Reason','Threat']) : '<div class="empty">No connections on known-malicious ports, IPs or domains ✓</div>';
      const cr=(r.connections||[]).map(x=>`<tr><td>${x.proto}</td><td class="mono">${x.local}</td><td class="mono">${x.remote}</td><td>${x.state}</td><td><span class="tag ${x.risk}">${cap(x.risk)}</span></td><td>${x.note||''}</td></tr>`).join('');
      co.innerHTML = cr ? threatTable(cr,['Proto','Local','Remote','State','Risk','Note']) : '<div class="empty">No active connections.</div>';
    };
    host.querySelector('#netReload').onclick=load; load();
  }
  if(name==='quarantine'){
    const load=async()=>{ const out=host.querySelector('#qOut'); out.innerHTML='<div class="scanning"><span class="dot"></span> Loading…</div>';
      const r=await invoke('quarantine_list'); if(!r){out.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      if(r.error||!r.items||!r.items.length){out.innerHTML='<div class="empty">Vault is empty.</div>';return;}
      const rows=r.items.map(i=>`<tr><td>${i.at}</td><td class="mono">${i.path}</td><td><span class="tag malicious">${i.threat}</span></td><td>${i.size} B</td><td>
        <button class="rowbtn" data-rest="${i.id}">Restore</button><button class="rowbtn danger" data-del="${i.id}">Delete</button></td></tr>`).join('');
      out.innerHTML=threatTable(rows,['Time','Original Path','Threat','Size','Actions']);
      out.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{await invoke('quarantine_remove',{id:b.dataset.del});toast('Deleted');load();});
      out.querySelectorAll('[data-rest]').forEach(b=>b.onclick=async()=>{const r2=await invoke('quarantine_restore',{id:b.dataset.rest,dest:'/tmp/restored_'+b.dataset.rest.slice(0,8)});if(r2&&r2.message)toast(r2.message);}); };
    host.querySelector('#qReload').onclick=load; load();
  }
  if(name==='sandbox'){
    const go=async(p)=>{ const out=host.querySelector('#sbOut'); if(!p){toast('Choose a file first');return;}
      out.innerHTML='<div class="scanning"><span class="dot"></span> Emulating…</div>';
      const r=await invoke('emulate_file',{path:p}); if(!r){out.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      if(r.error){out.innerHTML=`<div class="empty">${r.error}</div>`;return;}
      const vr=(r.verdicts||[]).map(v=>`<tr><td><span class="tag ${v.level}">${cap(v.level)}</span></td><td>${v.signature}</td><td>${v.detail||''}</td><td>${(v.mitre||[]).join(', ')}</td></tr>`).join('');
      const ex=(r.exploits||[]).map(e=>`<li><i data-ic="alert"></i>${e}</li>`).join('');
      out.innerHTML=`<div class="page-sub" style="margin-bottom:10px">Disposition <span class="tag ${r.disposition}">${cap(r.disposition)}</span> · ${r.bytes} bytes · ${r.instructions} instructions · MITRE ${(r.techniques||[]).join(', ')||'-'}</div>`
        + (vr?threatTable(vr,['Severity','Signature','Detail','MITRE']):'<div class="empty">No anti-evasion or shellcode techniques detected ✓</div>')
        + (ex?`<div class="panel" style="margin-top:12px"><div class="panel-h">EXPLOIT STAGING</div><ul class="feature-list" style="margin-top:10px">${ex}</ul></div>`:'');
      paintIcons(out); };
    host.querySelector('#sbGo').onclick=()=>go(host.querySelector('#sbPath').value);
    host.querySelector('#sbBrowse').onclick=async()=>{const p=await invoke('pick_file'); if(p) host.querySelector('#sbPath').value=p;};
  }
  if(name==='anomaly'){
    const path=()=>host.querySelector('#anPath').value;
    host.querySelector('#anBrowse').onclick=async()=>{const p=await invoke('pick_file'); if(p) host.querySelector('#anPath').value=p;};
    host.querySelector('#anLearn').onclick=async()=>{ const out=host.querySelector('#anOut'); if(!path()){toast('Choose a trace first');return;}
      out.innerHTML='<div class="scanning"><span class="dot"></span> Learning baseline…</div>';
      const r=await invoke('anomaly_learn',{path:path()}); if(!r){out.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      if(r.error){out.innerHTML=`<div class="empty">${r.error}</div>`;return;}
      out.innerHTML=`<div class="page-sub">${r.message}</div>`; toast(r.message, r.trained?'success':'info'); };
    host.querySelector('#anScore').onclick=async()=>{ const out=host.querySelector('#anOut'); if(!path()){toast('Choose a trace first');return;}
      out.innerHTML='<div class="scanning"><span class="dot"></span> Scoring against baseline…</div>';
      const r=await invoke('anomaly_score',{path:path()}); if(!r){out.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      if(r.error){out.innerHTML=`<div class="empty">${r.error}</div>`;return;}
      if(!r.trained){out.innerHTML=`<div class="empty">${r.message}</div>`;return;}
      const rows=(r.anomalies||[]).map(v=>`<tr><td><span class="tag ${v.level}">${cap(v.level)}</span></td><td>${v.signature}</td><td>${v.detail||''}</td></tr>`).join('');
      out.innerHTML=rows?threatTable(rows,['Severity','Signature','Detail']):'<div class="empty">No anomalies relative to the learned baseline ✓</div>'; };
  }
  if(name==='behavior'){
    host.querySelector('#bhBrowse').onclick=async()=>{const p=await invoke('pick_file'); if(p) host.querySelector('#bhPath').value=p;};
    host.querySelector('#bhGo').onclick=async()=>{ const out=host.querySelector('#bhOut'); const p=host.querySelector('#bhPath').value; if(!p){toast('Choose a trace first');return;}
      out.innerHTML='<div class="scanning"><span class="dot"></span> Analyzing trace…</div>';
      const r=await invoke('behavior_analyze',{path:p}); if(!r){out.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      if(r.error){out.innerHTML=`<div class="empty">${r.error}</div>`;return;}
      const rows=(r.verdicts||[]).map(v=>`<tr><td><span class="tag ${v.level}">${cap(v.level)}</span></td><td>${v.signature}</td><td>${v.detail||''}</td><td>${(v.mitre||[]).join(', ')}</td></tr>`).join('');
      out.innerHTML=`<div class="page-sub" style="margin:8px 0">Disposition <span class="tag ${r.disposition}">${cap(r.disposition)}</span> · MITRE ${(r.techniques||[]).join(', ')||'-'}</div>`
        +(rows?threatTable(rows,['Severity','Signature','Detail','MITRE']):'<div class="empty">No malicious behavior detected ✓</div>'); };
  }
  if(name==='reports'){
    const load=async()=>{ const out=host.querySelector('#rpOut'), k=host.querySelector('#rpKpis');
      const r=await invoke('scan_history'); if(!r){out.innerHTML='<div class="empty">Run inside the app.</div>';return;}
      const h=r.history||[], t=r.totals||{};
      if(k) k.innerHTML=[['Scans',h.length],['Files Scanned',(t.scanned||0).toLocaleString()],['Malicious',t.malicious||0],['Suspicious',t.suspicious||0]]
        .map(([l,v])=>`<div class="stat"><div class="sv">${v}</div><div class="sl">${l}</div></div>`).join('');
      const rows=h.map(x=>{const thr=(x.malicious||0)+(x.suspicious||0); let when='-'; try{when=new Date((x.ts||0)*1000).toLocaleString();}catch(_){}
        return `<tr><td>${when}</td><td>${x.source||''}</td><td class="mono">${x.path||''}</td><td>${x.scanned||0}</td><td><span class="tag ${thr>0?'malicious':'clean'}">${thr}</span></td><td>${x.ms||0} ms</td></tr>`;}).join('');
      out.innerHTML=rows?threatTable(rows,['Time','Source','Path','Scanned','Threats','Duration']):'<div class="empty">No scans recorded yet - run a scan from Scan Center.</div>'; };
    const exp=async(fmt)=>{ if(!TAURI){toast('Run inside the app to export');return;} const r=await invoke('export_report',{format:fmt}); if(r&&r.message) toast(r.message, r.ok?'success':'alert'); };
    host.querySelector('#rpJson').onclick=()=>exp('json');
    host.querySelector('#rpCsv').onclick=()=>exp('csv');
    host.querySelector('#rpHtml').onclick=()=>exp('html');
    host.querySelector('#rpClear').onclick=async()=>{const r=await invoke('clear_history'); if(r&&r.message)toast(r.message); load();};
    load();
  }
}
function setPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active', n.dataset.page===name));
  const app=document.querySelector('.app');
  if(name==='dashboard'){ app.classList.remove('page-mode'); refresh(); return; }
  app.classList.add('page-mode');
  const host=document.getElementById('pageHost');
  host.innerHTML=(PAGES[name]||(()=>'<div class="empty">Coming soon.</div>'))();
  paintIcons(host); bindPage(name, host);
}

async function boot(){
  // Show the real app version (matches the release tag when CI injects it).
  const ver = await invoke('app_version');
  if(ver){ const bv=document.getElementById('brandVer'); if(bv) bv.textContent='v'+ver; window.__APPVER='v'+ver; }

  await refresh();

  // Collapsible left menu.
  document.getElementById('menuToggle').addEventListener('click',()=>{
    document.querySelector('.app').classList.toggle('collapsed');
  });

  // Sidebar navigation -> page router.
  document.querySelectorAll('.nav-item[data-page]').forEach(n=>n.addEventListener('click',()=>setPage(n.dataset.page)));
  // Generic links (top-bar gear, "View All …") jump to a page too.
  document.querySelectorAll('[data-link]').forEach(n=>n.addEventListener('click',()=>setPage(n.dataset.link)));

  // Notification center (bell).
  wireBell();

  // Action buttons. Vault actions navigate to the Quarantine page; scans run.
  document.querySelectorAll('[data-act]').forEach(b=>b.addEventListener('click',async()=>{
    const act=b.getAttribute('data-act');
    if(act==='quarantine'||act==='restore'){ setPage('quarantine'); return; }
    const res=await invoke('run_action',{action:act});
    if(res && res.message) toast(res.message);
    refresh();
  }));

  // Threat-intel update (downloads abuse.ch feeds, hot-reloads signatures).
  document.getElementById('updateIntel').addEventListener('click',async()=>{
    if(!TAURI){ toast('Run inside the app to download live feeds'); return; }
    toast('Downloading threat-intel feeds…');
    const res=await invoke('update_intel');
    if(res && res.message) toast(res.message);
    refresh();
  });

  if(TAURI){
    const win=window.__TAURI__.window.getCurrentWindow();
    document.querySelector('[data-win=min]').onclick=()=>win.minimize();
    document.querySelector('[data-win=max]').onclick=()=>win.toggleMaximize();
    document.querySelector('[data-win=close]').onclick=()=>win.close();

    // Real-time metrics stream (emitted every 2s by the Rust backend).
    await window.__TAURI__.event.listen('metrics', e=>{
      const m=e.payload; if(!m) return;
      renderSystem({os:m.os+' ('+m.arch+')',cpu:m.cpu,ram:m.ram,disk:m.disk,net:m.net});
      document.getElementById('sb-net-down').textContent=m.net;
    });
    // Every native notification is mirrored here -> log it in the bell.
    await window.__TAURI__.event.listen('alert', e=>{ if(e.payload) pushNotif(e.payload); });

    // Engine finished loading signatures in the background -> refresh counts.
    await window.__TAURI__.event.listen('engine-ready', ()=>refresh());

    // Quick Scan triggered from the system tray.
    await window.__TAURI__.event.listen('tray-quickscan', ()=>{
      const b=document.querySelector('[data-act="quick"]'); if(b) b.click();
    });

    // Live kernel exec stream (Process Sentinel monitor).
    await window.__TAURI__.event.listen('exec', e=>{
      if(!e.payload) return;
      EXECS.unshift(e.payload); if(EXECS.length>80) EXECS.length=80;
      renderExecs();
      if(e.payload.risk==='malicious'||e.payload.risk==='suspicious')
        toast('⚠ '+e.payload.name+' ['+(e.payload.signature||e.payload.risk)+']','alert');
    });
    await window.__TAURI__.event.listen('exec-error', e=>{
      toast('Live monitor: '+((e.payload&&e.payload.message)||'unavailable'),'alert');
    });

    // Scheduled auto-update finished -> refresh counts and notify.
    await window.__TAURI__.event.listen('intel', e=>{
      const p=e.payload||{};
      if(p.added>0) toast('Auto-update · '+p.added+' new indicators · '+(p.signatures||0)+' signatures');
      refresh();
    });

    // Periodic full refresh so counts / processes / chart stay live.
    setInterval(refresh, 4000);

    // Listeners are now fully registered - fire the startup greeting.
    invoke('app_ready');
  }

  // Optional deep-link: index.html?page=scan
  const p=new URLSearchParams(location.search).get('page');
  if(p) setPage(p);
}
// ---- Notification center (bell + history) ----
const NOTIF = [];
function escH(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function notifTime(ts){ try{return new Date((ts||0)*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});}catch(_){return '';} }
function pushNotif(n){
  NOTIF.unshift({title:n.title||'Notification', body:n.body||'', level:n.level||'info',
                 ts:n.ts||Math.floor(Date.now()/1000), read:false});
  if(NOTIF.length>60) NOTIF.length=60;
  renderNotifs();
}
function renderNotifs(){
  const list=document.getElementById('notifList'), badge=document.getElementById('bellBadge'),
        bell=document.getElementById('bellBtn');
  if(!list) return;
  const unread=NOTIF.filter(n=>!n.read).length;
  if(badge){ badge.textContent=unread>9?'9+':String(unread); badge.classList.toggle('on', unread>0); }
  if(bell) bell.classList.toggle('has-unread', unread>0);
  list.innerHTML = NOTIF.length
    ? NOTIF.map(n=>`<div class="notif-item ni-${n.level}${n.read?'':' unread'}">
        <span class="ni-bar"></span>
        <div class="ni-body"><div class="ni-title">${escH(n.title)}</div><div class="ni-text">${escH(n.body)}</div></div>
        <div class="ni-time">${notifTime(n.ts)}</div></div>`).join('')
    : '<div class="notif-empty">No notifications yet</div>';
}
function wireBell(){
  const bellBtn=document.getElementById('bellBtn'), panel=document.getElementById('notifPanel');
  if(!bellBtn||!panel) return;
  bellBtn.onclick=e=>{ e.stopPropagation(); const willOpen=panel.hidden; panel.hidden=!willOpen;
    if(willOpen){ NOTIF.forEach(n=>n.read=true); renderNotifs(); } };
  document.addEventListener('click',e=>{ if(!panel.hidden && !panel.contains(e.target) && !bellBtn.contains(e.target)) panel.hidden=true; });
  const r=document.getElementById('notifRead'); if(r) r.onclick=e=>{e.stopPropagation();NOTIF.forEach(n=>n.read=true);renderNotifs();};
  const c=document.getElementById('notifClear'); if(c) c.onclick=e=>{e.stopPropagation();NOTIF.length=0;renderNotifs();};
}

// ---- Live exec monitor buffer (kernel cn_proc stream) ----
const EXECS = [];
function renderExecs(){
  const el=document.getElementById('senLive'); if(!el) return;
  if(!EXECS.length){ el.innerHTML='<div class="empty">Waiting for exec events… (press “Start Live Monitor”; needs root)</div>'; return; }
  const rows=EXECS.map(x=>`<tr><td>${x.pid}</td><td>${x.name}</td><td class="mono">${x.path}</td><td><span class="tag ${x.risk||'clean'}">${cap(x.risk||'clean')}</span></td><td>${x.signature||''}</td></tr>`).join('');
  el.innerHTML=threatTable(rows,['PID','Process','Image','Risk','Signature']);
}

function toast(msg, type){
  const t=document.createElement('div');
  t.className='toast toast-'+(type||'info');
  t.innerHTML='<span class="toast-bar"></span><span class="toast-msg"></span>';
  t.querySelector('.toast-msg').textContent=msg;
  document.body.appendChild(t);
  requestAnimationFrame(()=>t.classList.add('show'));
  setTimeout(()=>{ t.classList.remove('show'); setTimeout(()=>t.remove(),320); }, 3400);
}
document.addEventListener('DOMContentLoaded',boot);
