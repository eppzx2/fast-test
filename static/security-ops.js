(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const nativeFetch = window.fetch.bind(window);
  const auth = { enabled:false, username:"local", role:"admin", csrf:"" };
  const rank = {viewer:10, analyst:20, admin:30};
  let selectedCase = null;

  const text = (v) => String(v ?? "");
  const html = (v) => text(v).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
  const when = (v) => { if(!v) return "—"; const d=new Date(v); return Number.isNaN(d.getTime())?text(v):d.toLocaleString(); };
  const can = (role) => (rank[auth.role]||0) >= (rank[role]||999);

  async function api(url, options={}) {
    const res = await window.fetch(url, options);
    let data={}; try{ data=await res.json(); }catch(_e){}
    if(!res.ok) throw new Error(data.message || `Request failed (${res.status})`);
    return data;
  }

  function meta(eyebrow,title,subtitle){
    if($("pageEyebrow")) $("pageEyebrow").textContent=eyebrow;
    if($("pageTitle")) $("pageTitle").textContent=title;
    if($("pageSubtitle")) $("pageSubtitle").textContent=subtitle;
  }

  function activate(name){
    document.querySelectorAll(".view").forEach(el=>el.classList.toggle("active",el.id===`view-${name}`));
    document.querySelectorAll(".nav-btn").forEach(el=>el.classList.toggle("active",el.dataset.view===name));
    if(name==="incidents"){ meta("Security operations","Incidents","Triage real FAST detections and correlated activity."); loadIncidents(); }
    if(name==="validation"){ meta("Detection engineering","Detection Validation","Validate FAST rules against real Wazuh alerts — no synthetic telemetry."); loadValidation(); }
    window.scrollTo({top:0,behavior:"smooth"});
  }

  function navButton(view,icon,label){
    const b=document.createElement("button"); b.className="nav-btn"; b.dataset.view=view;
    const i=document.createElement("span"); i.className="nav-icon"; i.textContent=icon;
    b.append(i,document.createTextNode(label)); b.addEventListener("click",()=>activate(view)); return b;
  }

  function installNav(){
    document.querySelector('.nav-btn[data-view="simulation"]')?.remove();
    $("view-simulation")?.remove();
    const nav=document.querySelector(".nav"); if(!nav) return;
    if(!nav.querySelector('[data-view="incidents"]')) nav.insertBefore(navButton("incidents","◆","Incidents"),nav.querySelector('[data-view="detections"]'));
    if(!nav.querySelector('[data-view="validation"]')) nav.insertBefore(navButton("validation","⚡","Detection Validation"),nav.querySelector('[data-view="system"]'));
  }

  async function initAuth(){
    try{
      const res=await nativeFetch("/api/auth/me",{cache:"no-store"}); if(!res.ok) return;
      const data=await res.json(); auth.enabled=!!data.enabled; auth.username=data.username||"local"; auth.role=data.role||"viewer"; auth.csrf=data.csrf_token||"";
      if(!window.__FAST_SECURE_FETCH__){
        window.__FAST_SECURE_FETCH__=true;
        window.fetch=async(input,init={})=>{
          const next={...init}; const method=String(next.method||"GET").toUpperCase(); const url=typeof input==="string"?input:(input?.url||"");
          const same=url.startsWith("/")||url.startsWith(location.origin);
          if(auth.enabled&&auth.csrf&&same&&["POST","PUT","PATCH","DELETE"].includes(method)){ const h=new Headers(next.headers||{}); h.set("X-CSRF-Token",auth.csrf); next.headers=h; }
          const r=await nativeFetch(input,next); if(auth.enabled&&same&&r.status===401) location.assign(`/login?next=${encodeURIComponent(location.pathname)}`); return r;
        };
      }
      renderIdentity();
    }catch(_e){}
  }

  function renderIdentity(){
    const actions=document.querySelector(".top-actions"); if(!actions||$("fastIdentity")) return;
    const chip=document.createElement("div"); chip.id="fastIdentity"; chip.className="identity-chip"+(auth.enabled?"":" local");
    chip.innerHTML=`<span class="identity-dot"></span>${html(auth.username)} · ${html(auth.role)}`; actions.prepend(chip);
    const sync=$("syncIntelligenceBtn"); if(sync&&auth.enabled&&!can("admin")){ sync.disabled=true; sync.title="Admin role required"; }
    if(auth.enabled){ const b=document.createElement("button"); b.className="btn btn-ghost"; b.textContent="Sign out"; b.onclick=async()=>{try{await api("/logout",{method:"POST"});}finally{location.assign("/login");}}; actions.appendChild(b); }
  }

  function installIncidents(){
    if($("view-incidents")) return; const main=document.querySelector("main.main"); if(!main) return;
    const s=document.createElement("section"); s.className="view"; s.id="view-incidents";
    s.innerHTML=`<div class="section-head"><div><h2>Incident Workflow</h2><p>Wazuh remains the alert source of truth; FAST stores only analyst status, assignee and notes.</p></div><button class="btn" id="refreshIncidents">Refresh</button></div>
    <div class="ops-metrics"><div class="card ops-metric"><span>Open</span><strong id="incOpen">0</strong></div><div class="card ops-metric"><span>Critical / High</span><strong id="incHigh">0</strong></div><div class="card ops-metric"><span>Correlations</span><strong id="incCorr">0</strong></div></div>
    <div class="platform-grid incident-layout"><div class="card table-card"><div class="card-head padded-head"><div><div class="card-kicker">Real Wazuh detections</div><div class="card-title">Detection Cases</div></div><span class="live-badge" id="incBadge">LIVE</span></div><div class="table-scroll"><table id="incidentTable"><thead><tr><th>Time</th><th>Detection</th><th>Agent</th><th>Source</th><th>Priority</th><th>Status</th><th>Assignee</th><th></th></tr></thead><tbody id="incBody"></tbody></table><div class="platform-empty" id="incEmpty">No FAST detection cases.</div></div></div>
    <div class="card case-panel"><div class="card-head"><div><div class="card-kicker">Analyst workspace</div><div class="card-title">Case Details</div></div></div><div id="caseEmpty" class="platform-empty compact">Select a case.</div><div id="caseEditor" hidden><div class="case-summary" id="caseSummary"></div><label class="ops-label">Status</label><select class="control" id="caseStatus"><option value="new">New</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False Positive</option></select><label class="ops-label">Assignee</label><input class="control" id="caseAssignee" maxlength="120"><label class="ops-label">Notes</label><textarea class="control ops-textarea" id="caseNotes" maxlength="4000"></textarea><button class="btn btn-primary full-width" id="saveCase">Save Analyst State</button><div class="platform-source-note" id="casePermission"></div></div></div></div>
    <div class="card" style="margin-top:16px"><div class="card-head"><div><div class="card-kicker">Correlation engine</div><div class="card-title">Related Activity</div></div><span class="live-badge">REAL ALERTS ONLY</span></div><div id="corrList" class="correlation-list"></div></div>`;
    main.insertBefore(s,$("view-detections")); $("refreshIncidents").onclick=loadIncidents; $("saveCase").onclick=saveCase;
  }

  function renderIncidents(items){
    const body=$("incBody"); body.textContent="";
    items.forEach(item=>{ const tr=document.createElement("tr");
      const cols=[when(item.timestamp),item.attack_type||"FAST detection",item.agent_name||item.agent_id||"Unknown",item.source_ip||"—"];
      cols.forEach((v,i)=>{const td=document.createElement("td"); if(i===0||i===3)td.className="mono"; td.textContent=text(v); tr.appendChild(td);});
      const pr=document.createElement("td"); pr.innerHTML=`<span class="priority ${html(item.priority)}">${html(item.priority)}</span>`;
      const st=document.createElement("td"); st.innerHTML=`<span class="case-status ${html(item.status)}">${html(item.status).replace("_"," ")}</span>`;
      const as=document.createElement("td"); as.textContent=item.assignee||"Unassigned";
      const act=document.createElement("td"); const b=document.createElement("button"); b.className="btn btn-small"; b.textContent="Open"; b.onclick=()=>selectCase(item); act.appendChild(b);
      tr.append(pr,st,as,act); body.appendChild(tr);
    });
    $("incEmpty").style.display=items.length?"none":"block";
    $("incOpen").textContent=items.filter(x=>!["resolved","false_positive"].includes(x.status)).length;
    $("incHigh").textContent=items.filter(x=>["critical","high"].includes(x.priority)).length;
  }

  function selectCase(item){
    selectedCase=item; $("caseEmpty").hidden=true; $("caseEditor").hidden=false;
    $("caseSummary").innerHTML=`<strong>${html(item.attack_type||"FAST detection")}</strong><span>Rule ${html(item.rule_id)} · ${html(item.agent_name||item.agent_id||"Unknown")}</span><span>${html(when(item.timestamp))}</span>`;
    $("caseStatus").value=item.status||"new"; $("caseAssignee").value=item.assignee||""; $("caseNotes").value=item.notes||"";
    const writable=!auth.enabled||can("analyst"); [$("caseStatus"),$("caseAssignee"),$("caseNotes"),$("saveCase")].forEach(el=>el.disabled=!writable);
    $("casePermission").textContent=writable?"Analyst state is audited; Wazuh alert data is read-only.":"Analyst role required to update cases.";
  }

  async function saveCase(){
    if(!selectedCase) return; const btn=$("saveCase"); btn.disabled=true;
    try{ await api(`/api/security/incidents/${encodeURIComponent(selectedCase.event_id)}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:$("caseStatus").value,assignee:$("caseAssignee").value,notes:$("caseNotes").value})}); await loadIncidents(); }
    catch(e){ $("casePermission").textContent=e.message; } finally{btn.disabled=auth.enabled&&!can("analyst");}
  }

  function renderCorrelations(items){
    $("incCorr").textContent=items.length; const list=$("corrList"); list.textContent="";
    if(!items.length){list.innerHTML='<div class="platform-empty compact">No related alert clusters in the current window.</div>';return;}
    items.forEach(x=>{const d=document.createElement("div");d.className="correlation-item";d.innerHTML=`<div><strong>${html(x.title)}</strong><span>${html(x.agent_name)} · ${html(x.source_ip||"local")} · ${html(x.event_count)} events</span></div><div class="corr-meta"><span class="risk-chip ${x.risk_score>=75?"critical":x.risk_score>=50?"high":"medium"}">${html(x.risk_score)}/100</span><span class="mono">${html((x.rule_ids||[]).join(", "))}</span></div>`;list.appendChild(d);});
  }

  async function loadIncidents(){
    try{const data=await api("/api/security/incidents?minutes=1440&limit=300",{cache:"no-store"}); renderIncidents(data.items||[]); renderCorrelations(data.correlations||[]); $("incBadge").textContent=data.sampled?"WAZUH LIVE · SAMPLED":"WAZUH LIVE"; $("incBadge").className="live-badge ok";}
    catch(e){renderIncidents([]);renderCorrelations([]);$("incEmpty").style.display="block";$("incEmpty").textContent=`Incidents unavailable: ${e.message}`;$("incBadge").textContent="UNAVAILABLE";$("incBadge").className="live-badge bad";}
  }

  function installValidation(){
    if($("view-validation")) return; const main=document.querySelector("main.main"); if(!main)return;
    const s=document.createElement("section");s.className="view";s.id="view-validation";
    s.innerHTML=`<div class="section-head"><div><h2>Detection Validation Lab</h2><p>Run existing lab scripts from the correct host; FAST verifies whether the expected real Wazuh rule fired.</p></div><button class="btn btn-primary" id="refreshValidation">Refresh Validation</button></div><div class="validation-grid" id="validationGrid"></div><div class="card" style="margin-top:16px"><div class="card-head"><div><div class="card-kicker">Real flow</div><div class="card-title">Attack → Wazuh Agent → Wazuh SIEM → Alert → FAST / TALON</div></div></div><div class="platform-flow compact-flow"><div class="flow-node"><div><div class="flow-step">01</div><div class="flow-title">Lab Activity</div></div></div><div class="flow-arrow">→</div><div class="flow-node"><div><div class="flow-step">02</div><div class="flow-title">Wazuh Agent</div></div></div><div class="flow-arrow">→</div><div class="flow-node core"><div><div class="flow-step">03</div><div class="flow-title">Wazuh SIEM</div></div></div><div class="flow-arrow">→</div><div class="flow-node"><div><div class="flow-step">04</div><div class="flow-title">Real Alert</div></div></div><div class="flow-arrow">→</div><div class="flow-node active"><div><div class="flow-step">05</div><div class="flow-title">FAST / TALON</div></div></div></div></div>`;
    main.insertBefore(s,$("view-system"));$("refreshValidation").onclick=loadValidation;
  }

  async function loadValidation(){
    const grid=$("validationGrid"); if(!grid)return;
    try{const data=await api("/api/security/validation",{cache:"no-store"});grid.textContent="";(data.items||[]).forEach(item=>{const d=document.createElement("div");d.className="card validation-card";d.innerHTML=`<div class="validation-top"><div><div class="card-kicker">Rule ${html(item.id)}</div><div class="card-title">${html(item.name)}</div></div><span class="validation-state ${html(item.validation)}">${html(item.validation)}</span></div><div class="validation-meta"><span>24h alerts <strong>${html(item.count_24h)}</strong></span><span>Last trigger <strong>${html(when(item.last_triggered))}</strong></span><span>Agent <strong>${html(item.last_agent||"—")}</strong></span></div><div class="sim-command"><div class="sim-command-title">${html(item.validation_host)} · copy only</div><code>${html(item.validation_command)}</code><small>Browser never executes attack scripts. PASS requires the real rule to be observed within ${html(data.fresh_minutes)} minutes.</small></div>`;grid.appendChild(d);});}
    catch(e){grid.innerHTML=`<div class="card platform-empty">Validation unavailable: ${html(e.message)}</div>`;}
  }

  function enhanceDetections(){
    const view=$("view-detections"); if(!view)return;
    view.querySelector(".section-head")?.replaceChildren();
    const head=view.querySelector(".section-head"); if(head)head.innerHTML='<div><h2>Detection Engineering</h2><p>Rule health, exact 24-hour alert volume, latest trigger and connected-agent coverage from Wazuh.</p></div><button class="btn" id="refreshDetectionHealth">Refresh</button>';
    if($("detectionCards")) $("detectionCards").className="grid detection-grid";
    $("refreshDetectionHealth")?.addEventListener("click",loadDetectionHealth);
  }

  async function loadDetectionHealth(){
    const el=$("detectionCards");if(!el)return;
    try{const data=await api("/api/security/detections",{cache:"no-store"});el.textContent="";(data.items||[]).forEach(item=>{const c=document.createElement("div");c.className="card detection-card";c.innerHTML=`<div class="detection-rule mono">RULE ${html(item.id)}</div><h3>${html(item.name)}</h3><p>${html(item.description)}</p><div class="detect-health"><span>Level <strong>${html(item.level)}</strong></span><span>Alerts 24h <strong>${html(item.alerts_24h)}</strong></span><span>Last <strong>${html(when(item.last_triggered))}</strong></span><span>Agents <strong>${html(item.active_agents)}/${html(item.total_agents)}</strong></span></div><div class="mitre">${(item.mitre||[]).map(x=>`<span>${html(x)}</span>`).join("")}</div>`;el.appendChild(c);});}
    catch(e){el.innerHTML=`<div class="card platform-empty">Detection health unavailable: ${html(e.message)}</div>`;}
  }

  function enhanceArchitecture(){
    const view=$("view-architecture");if(!view)return;
    view.innerHTML=`<div class="section-head"><div><h2>FAST Platform Architecture</h2><p>Wazuh is the active SIEM core, TALON is the threat-intelligence module, and future integrations remain clearly marked.</p></div><button class="btn" id="refreshRiskAssets">Refresh Assets</button></div><div class="fast-platform-shell"><div class="platform-core-head"><div><div class="platform-core-title">FAST · Unified Security Platform</div><div class="platform-core-sub">Security telemetry, analyst workflow, intelligence and integrations in one operational layer.</div></div><span class="platform-state">Platform Active</span></div><div class="module-grid"><div class="module-card active"><div class="module-label">Core</div><div class="module-name">SIEM / Wazuh</div><div class="module-desc">Agents, telemetry, detection, indexing and Threat Hunting.</div><span class="module-state">Active</span></div><div class="module-card active"><div class="module-label">FAST module</div><div class="module-name">TALON</div><div class="module-desc">OSINT collection, normalization, scoring and IOC integration.</div><span class="module-state">Active</span></div>${["SOAR","PAM","EPM","DLP"].map(x=>`<div class="module-card future"><div class="module-label">Future integration</div><div class="module-name">${x}</div><div class="module-desc">Planned integration; no synthetic functionality is exposed.</div><span class="module-state">Coming Soon</span></div>`).join("")}</div></div><div class="card table-card" style="margin-top:16px"><div class="card-head padded-head"><div><div class="card-kicker">Wazuh + FAST risk engine</div><div class="card-title">Asset Catalog</div></div><div class="asset-summary"><span class="summary-chip"><strong id="opsAssetTotal">0</strong> assets</span><span class="summary-chip"><strong id="opsAssetHigh">0</strong> high risk</span><span class="live-badge" id="opsAssetBadge">LIVE</span></div></div><div class="table-scroll"><table id="opsAssetTable"><thead><tr><th>ID</th><th>Hostname</th><th>OS</th><th>IP</th><th>Status</th><th>Risk</th><th>Alerts 24h</th><th>Last Keepalive</th></tr></thead><tbody id="opsAssetBody"></tbody></table><div class="platform-empty" id="opsAssetEmpty">No assets returned.</div></div></div>`;
    $("refreshRiskAssets").onclick=loadRiskAssets;
  }

  async function loadRiskAssets(){
    const body=$("opsAssetBody");if(!body)return;
    try{const data=await api("/api/security/assets",{cache:"no-store"});body.textContent="";(data.items||[]).forEach(a=>{const tr=document.createElement("tr");tr.innerHTML=`<td class="mono">${html(a.id)}</td><td>${html(a.hostname)}</td><td>${html([a.os,a.os_version].filter(Boolean).join(" "))}</td><td class="mono">${html(a.ip)}</td><td><span class="asset-status ${html(a.status)}">${html(a.status)}</span></td><td><span class="risk-chip ${html(a.risk_band)}" title="${html((a.risk_reasons||[]).join(" · "))}">${html(a.risk_score)}/100</span></td><td class="mono">${html(a.alert_count||0)}</td><td class="mono">${html(when(a.last_keepalive))}</td>`;body.appendChild(tr);});$("opsAssetEmpty").style.display=data.items?.length?"none":"block";$("opsAssetTotal").textContent=data.items?.length||0;$("opsAssetHigh").textContent=(data.items||[]).filter(a=>["high","critical"].includes(a.risk_band)).length;$("opsAssetBadge").textContent=data.alert_sampled?"LIVE · SAMPLED":"WAZUH LIVE";$("opsAssetBadge").className="live-badge ok";}
    catch(e){body.textContent="";$("opsAssetEmpty").style.display="block";$("opsAssetEmpty").textContent=`Asset risk unavailable: ${e.message}`;$("opsAssetBadge").textContent="UNAVAILABLE";$("opsAssetBadge").className="live-badge bad";}
  }

  function installAudit(){
    const view=$("view-system");if(!view||$("auditPanel"))return;const p=document.createElement("div");p.id="auditPanel";p.className="card table-card";p.style.marginTop="16px";p.innerHTML='<div class="card-head padded-head"><div><div class="card-kicker">FAST audit trail</div><div class="card-title">Security Operations Activity</div></div><button class="btn btn-small" id="refreshAudit">Refresh</button></div><div class="table-scroll"><table id="auditTable"><thead><tr><th>Time</th><th>Actor</th><th>Role</th><th>Action</th><th>Object</th></tr></thead><tbody id="auditBody"></tbody></table><div class="platform-empty" id="auditEmpty">No audit events yet.</div></div>';view.appendChild(p);$("refreshAudit").onclick=loadAudit;
  }

  async function loadAudit(){
    const body=$("auditBody");if(!body)return;if(auth.enabled&&!can("admin")){body.textContent="";$("auditEmpty").style.display="block";$("auditEmpty").textContent="Audit trail is Admin-only.";return;}
    try{const data=await api("/api/security/audit?limit=100",{cache:"no-store"});body.textContent="";(data.items||[]).forEach(i=>{const tr=document.createElement("tr");[when(i.timestamp),i.actor,i.role,i.action,[i.object_type,i.object_id].filter(Boolean).join(":")||"—"].forEach((v,n)=>{const td=document.createElement("td");if(n===0||n===4)td.className="mono";td.textContent=text(v);tr.appendChild(td);});body.appendChild(tr);});$("auditEmpty").style.display=data.items?.length?"none":"block";}
    catch(e){body.textContent="";$("auditEmpty").style.display="block";$("auditEmpty").textContent=`Audit unavailable: ${e.message}`;}
  }

  function hookExistingNav(){
    document.querySelector('[data-view="detections"]')?.addEventListener("click",()=>setTimeout(()=>{meta("Detection engineering","FAST Detections","Live rule health and coverage from Wazuh.");loadDetectionHealth();},0));
    document.querySelector('[data-view="architecture"]')?.addEventListener("click",()=>setTimeout(()=>{meta("Platform","FAST Architecture","Unified architecture, live assets and transparent risk scoring.");loadRiskAssets();},0));
    document.querySelector('[data-view="system"]')?.addEventListener("click",()=>setTimeout(loadAudit,0));
  }

  installNav(); installIncidents(); installValidation(); enhanceDetections(); enhanceArchitecture(); installAudit(); hookExistingNav();
  initAuth();
  setInterval(()=>{if($("view-incidents")?.classList.contains("active"))loadIncidents();if($("view-validation")?.classList.contains("active"))loadValidation();},12000);
})();
