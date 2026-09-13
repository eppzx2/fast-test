(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const text = (value) => String(value ?? "");
  const html = (value) => text(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
  const when = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? text(value) : date.toLocaleString();
  };

  async function api(url) {
    const response = await window.fetch(url, { cache: "no-store" });
    let data = {};
    try { data = await response.json(); } catch (_error) {}
    if (!response.ok) throw new Error(data.message || `Request failed (${response.status})`);
    return data;
  }

  function setMeta() {
    if ($("pageEyebrow")) $("pageEyebrow").textContent = "Threat framework";
    if ($("pageTitle")) $("pageTitle").textContent = "MITRE ATT&CK Mapping";
    if ($("pageSubtitle")) $("pageSubtitle").textContent = "See which ATT&CK tactics and techniques FAST maps, and which mapped techniques were observed in real Wazuh alerts.";
  }

  function activate() {
    document.querySelectorAll(".view").forEach(el => el.classList.toggle("active", el.id === "view-mitre"));
    document.querySelectorAll(".nav-btn").forEach(el => el.classList.toggle("active", el.dataset.view === "mitre"));
    setMeta();
    loadMitre();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function installNav() {
    const nav = document.querySelector(".nav");
    if (!nav || nav.querySelector('[data-view="mitre"]')) return;
    const button = document.createElement("button");
    button.className = "nav-btn";
    button.dataset.view = "mitre";
    const icon = document.createElement("span");
    icon.className = "nav-icon";
    icon.textContent = "▦";
    button.append(icon, document.createTextNode("MITRE ATT&CK"));
    button.addEventListener("click", activate);
    const before = nav.querySelector('[data-view="validation"]') || nav.querySelector('[data-view="system"]');
    nav.insertBefore(button, before || null);
  }

  function installView() {
    if ($("view-mitre")) return;
    const main = document.querySelector("main.main");
    if (!main) return;
    const section = document.createElement("section");
    section.className = "view";
    section.id = "view-mitre";
    section.innerHTML = `
      <div class="section-head">
        <div>
          <h2>MITRE ATT&CK Mapping</h2>
          <p>FAST rule coverage mapped to MITRE ATT&CK Enterprise. Mapping and observed activity are shown separately so the UI never presents unused techniques as live attacks.</p>
        </div>
        <button class="btn" id="refreshMitre">Refresh Mapping</button>
      </div>
      <div class="ops-metrics mitre-summary">
        <div class="card ops-metric"><span>Mapped Tactics</span><strong id="mitreMappedTactics">0</strong></div>
        <div class="card ops-metric"><span>Observed Tactics</span><strong id="mitreObservedTactics">0</strong></div>
        <div class="card ops-metric"><span>Mapped Techniques</span><strong id="mitreMappedTechniques">0</strong></div>
        <div class="card ops-metric"><span>Mapped Alerts 24h</span><strong id="mitreAlerts">0</strong></div>
      </div>
      <div class="card mitre-panel">
        <div class="card-head padded-head">
          <div><div class="card-kicker">Enterprise matrix</div><div class="card-title">FAST ATT&CK Coverage</div></div>
          <div class="mitre-legend"><span><i class="legend-dot observed"></i>Observed</span><span><i class="legend-dot mapped"></i>Mapped</span><span><i class="legend-dot empty"></i>Not mapped</span></div>
        </div>
        <div class="mitre-matrix" id="mitreMatrix"></div>
        <div class="platform-source-note mitre-note" id="mitreNote">Mapped means a FAST rule declares the technique. Observed means Wazuh stored a real matching alert in the last 24 hours.</div>
      </div>
      <div class="card table-card" style="margin-top:16px">
        <div class="card-head padded-head"><div><div class="card-kicker">Technique detail</div><div class="card-title">Mapped FAST Detections</div></div><span class="live-badge" id="mitreSourceBadge">LIVE</span></div>
        <div class="table-scroll">
          <table id="mitreTechniqueTable">
            <thead><tr><th>Tactic</th><th>Technique</th><th>FAST Rule</th><th>Detection</th><th>Alerts 24h</th><th>Last Observed</th></tr></thead>
            <tbody id="mitreTechniqueBody"></tbody>
          </table>
          <div class="platform-empty" id="mitreTechniqueEmpty">No FAST techniques are mapped.</div>
        </div>
      </div>`;
    const before = $("view-validation") || $("view-system");
    main.insertBefore(section, before || null);
    $("refreshMitre").addEventListener("click", loadMitre);
  }

  function renderMatrix(tactics) {
    const matrix = $("mitreMatrix");
    matrix.textContent = "";
    (tactics || []).forEach(tactic => {
      const card = document.createElement("div");
      const state = tactic.observed ? "observed" : tactic.mapped ? "mapped" : "empty";
      card.className = `mitre-tactic ${state}`;
      const techniques = (tactic.technique_ids || []).map(id => `<span class="mitre-id">${html(id)}</span>`).join("");
      card.innerHTML = `
        <div class="mitre-tactic-head"><span class="mono">${html(tactic.id)}</span><span class="mitre-state">${state === "empty" ? "not mapped" : state}</span></div>
        <strong>${html(tactic.name)}</strong>
        <div class="mitre-tactic-meta"><span>${html(tactic.technique_count || 0)} techniques</span><span>${html(tactic.alerts || 0)} alerts</span></div>
        <div class="mitre-technique-chips">${techniques || '<span class="mitre-muted">no current FAST mapping</span>'}</div>`;
      matrix.appendChild(card);
    });
  }

  function techniqueUrl(id) {
    const parts = text(id).split(".");
    return parts.length > 1
      ? `https://attack.mitre.org/techniques/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}/`
      : `https://attack.mitre.org/techniques/${encodeURIComponent(parts[0])}/`;
  }

  function renderTechniques(items) {
    const body = $("mitreTechniqueBody");
    body.textContent = "";
    (items || []).forEach(item => {
      const tactics = (item.tactics || []).map(tactic => tactic.name).join(", ") || "—";
      const rules = (item.rule_ids || []).join(", ") || "—";
      const detections = (item.detections || []).join(", ") || "—";
      const row = document.createElement("tr");
      row.innerHTML = `<td>${html(tactics)}</td><td><a class="mitre-link" href="${techniqueUrl(item.id)}" target="_blank" rel="noopener noreferrer"><span class="mono">${html(item.id)}</span> ${html(item.name)}</a></td><td class="mono">${html(rules)}</td><td>${html(detections)}</td><td class="mono">${html(item.alerts || 0)}</td><td class="mono">${html(when(item.last_triggered))}</td>`;
      body.appendChild(row);
    });
    $("mitreTechniqueEmpty").style.display = items?.length ? "none" : "block";
  }

  async function loadMitre() {
    const badge = $("mitreSourceBadge");
    try {
      const data = await api("/api/security/mitre?minutes=1440");
      const summary = data.summary || {};
      $("mitreMappedTactics").textContent = summary.mapped_tactics || 0;
      $("mitreObservedTactics").textContent = summary.observed_tactics || 0;
      $("mitreMappedTechniques").textContent = summary.mapped_techniques || 0;
      $("mitreAlerts").textContent = summary.alerts || 0;
      renderMatrix(data.tactics || []);
      renderTechniques(data.techniques || []);
      $("mitreNote").textContent = data.note || "Coverage is based on current FAST custom rules and real Wazuh observations.";
      badge.textContent = "WAZUH LIVE";
      badge.className = "live-badge ok";
    } catch (error) {
      renderMatrix([]);
      renderTechniques([]);
      $("mitreNote").textContent = `MITRE mapping unavailable: ${error.message}`;
      badge.textContent = "UNAVAILABLE";
      badge.className = "live-badge bad";
    }
  }

  installNav();
  installView();
})();
