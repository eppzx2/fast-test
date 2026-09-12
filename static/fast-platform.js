(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const escText = (value) => String(value ?? "");
  const formatTime = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? escText(value) : date.toLocaleString();
  };

  function removeThreatFeedsNav() {
    // Threat-feed coverage already exists in Overview and IOC Database.
    // Keep the legacy view in the DOM because the original dashboard script
    // still refreshes its feed cards, but remove the redundant navigation tab.
    document.querySelector('.nav-btn[data-view="feeds"]')?.remove();
  }

  function setPageMeta(eyebrow, title, subtitle) {
    const eyebrowEl = $("pageEyebrow");
    const titleEl = $("pageTitle");
    const subtitleEl = $("pageSubtitle");
    if (eyebrowEl) eyebrowEl.textContent = eyebrow;
    if (titleEl) titleEl.textContent = title;
    if (subtitleEl) subtitleEl.textContent = subtitle;
  }

  function activateView(name) {
    document.querySelectorAll(".view").forEach((el) => {
      el.classList.toggle("active", el.id === `view-${name}`);
    });
    document.querySelectorAll(".nav-btn").forEach((el) => {
      el.classList.toggle("active", el.dataset.view === name);
    });
    if (name === "simulation") {
      setPageMeta(
        "Detection validation",
        "Attack Simulation",
        "Real Wazuh alerts from the existing FAST lab simulations — no fake telemetry."
      );
      loadLiveAlerts();
    } else if (name === "architecture") {
      loadAssets();
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function installSimulationNav() {
    const nav = document.querySelector(".nav");
    if (!nav || nav.querySelector('[data-view="simulation"]')) return;
    const button = document.createElement("button");
    button.className = "nav-btn";
    button.dataset.view = "simulation";
    const icon = document.createElement("span");
    icon.className = "nav-icon";
    icon.textContent = "⚡";
    button.append(icon, document.createTextNode("Attack Simulation"));
    const architecture = nav.querySelector('[data-view="architecture"]');
    nav.insertBefore(button, architecture || null);
    button.addEventListener("click", () => activateView("simulation"));
  }

  function installSimulationView() {
    if ($("view-simulation")) return;
    const main = document.querySelector("main.main");
    const architecture = $("view-architecture");
    if (!main) return;

    const section = document.createElement("section");
    section.className = "view";
    section.id = "view-simulation";
    section.innerHTML = `
      <div class="section-head">
        <div>
          <h2>Real Detection Flow</h2>
          <p>Run the existing lab simulator on the correct machine. FAST reads the resulting Wazuh alert from the Indexer and displays it here.</p>
        </div>
        <div class="section-actions">
          <button class="btn btn-primary" id="refreshLiveAlerts">Refresh Live Alerts</button>
        </div>
      </div>
      <div class="live-strip">
        <div class="live-left">
          <span class="status-dot" id="liveAlertDot"></span>
          <div class="live-copy">
            <div class="live-title" id="liveAlertTitle">Connecting to Wazuh Indexer…</div>
            <div class="live-note" id="liveAlertNote">Only rules 100200, 100211 and 100221 are shown.</div>
          </div>
        </div>
        <span class="live-badge" id="liveAlertBadge">LIVE</span>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-head"><div><div class="card-kicker">Demo pipeline</div><div class="card-title">Attack → Alert → FAST visibility</div></div></div>
        <div class="platform-flow">
          <div class="flow-node"><div><div class="flow-step">01 · Lab</div><div class="flow-title">Attack Simulation</div><div class="flow-desc">Existing SSH brute-force, port-scan or LOLBin simulator generates real activity.</div></div></div>
          <div class="flow-arrow">→</div>
          <div class="flow-node"><div><div class="flow-step">02 · Endpoint</div><div class="flow-title">Wazuh Agent</div><div class="flow-desc">The connected target agent collects the endpoint or audit event.</div></div></div>
          <div class="flow-arrow">→</div>
          <div class="flow-node core"><div><div class="flow-step">03 · SIEM</div><div class="flow-title">Wazuh SIEM</div><div class="flow-desc">Manager rules analyze the event and the Indexer stores the resulting alert.</div></div></div>
          <div class="flow-arrow">→</div>
          <div class="flow-node"><div><div class="flow-step">04 · Detection</div><div class="flow-title">Real Alert</div><div class="flow-desc">FAST rules 100200 / 100211 / 100221 identify the lab scenarios.</div></div></div>
          <div class="flow-arrow">→</div>
          <div class="flow-node active"><div><div class="flow-step">05 · Platform</div><div class="flow-title">FAST / TALON</div><div class="flow-desc">The platform surfaces the real alert while TALON supplies threat-intelligence context.</div></div></div>
        </div>
      </div>
      <div class="platform-grid platform-two" style="margin-bottom:16px">
        <div class="card table-card">
          <div class="card-head" style="padding:18px 18px 0"><div><div class="card-kicker">Wazuh Indexer</div><div class="card-title">Live FAST Alerts</div></div><div class="result-count" id="liveAlertCount">0 alerts</div></div>
          <div class="table-scroll">
            <table id="liveAlertsTable">
              <thead><tr><th>Time</th><th>Attack</th><th>Rule</th><th>Level</th><th>Agent</th><th>Source IP</th><th>Description</th></tr></thead>
              <tbody id="liveAlertsBody"></tbody>
            </table>
            <div class="platform-empty" id="liveAlertsEmpty">No matching FAST alerts in the selected time window yet.</div>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><div><div class="card-kicker">Existing repo scripts</div><div class="card-title">Run a lab scenario</div></div></div>
          <div class="sim-command"><div class="sim-command-title">SSH brute-force · Runner</div><code>./tests/acceptance/sim/simulate_brute_force.sh &lt;TARGET_IP&gt; nonexistent_bruteforce_test_user 8</code><small>Expected FAST rule: 100200. The target must have an Active Wazuh agent.</small></div>
          <div class="sim-command"><div class="sim-command-title">Port scan · Runner</div><code>./tests/acceptance/sim/simulate_port_scan.sh &lt;TARGET_IP&gt;</code><small>Expected correlated FAST rule: 100211.</small></div>
          <div class="sim-command"><div class="sim-command-title">LOLBin · Target</div><code>./tests/acceptance/sim/simulate_lolbin.sh</code><small>Run on the monitored Linux target. Expected FAST rule: 100221.</small></div>
          <div class="platform-source-note"><strong>Source of truth:</strong> Wazuh Indexer <span class="mono">wazuh-alerts-*</span>. FAST does not synthesize demo alerts.</div>
        </div>
      </div>`;
    main.insertBefore(section, architecture || null);
    $("refreshLiveAlerts")?.addEventListener("click", loadLiveAlerts);
  }

  function renderAlerts(items) {
    const body = $("liveAlertsBody");
    const empty = $("liveAlertsEmpty");
    const count = $("liveAlertCount");
    if (!body) return;
    body.textContent = "";
    items.forEach((alert) => {
      const tr = document.createElement("tr");
      const values = [
        formatTime(alert.timestamp),
        alert.attack_type || "FAST detection",
        alert.rule_id || "—",
        alert.level ?? "—",
        alert.agent_name || alert.agent_id || "Unknown",
        alert.source_ip || "—",
        alert.description || "",
      ];
      values.forEach((value, index) => {
        const td = document.createElement("td");
        if ([0, 2, 5].includes(index)) td.className = "mono";
        if (index === 3) {
          const severity = document.createElement("span");
          severity.className = "alert-severity";
          severity.textContent = escText(value);
          td.appendChild(severity);
        } else {
          td.textContent = escText(value);
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    if (empty) empty.style.display = items.length ? "none" : "block";
    if (count) count.textContent = `${items.length} alert${items.length === 1 ? "" : "s"}`;
  }

  async function loadLiveAlerts() {
    const title = $("liveAlertTitle");
    const note = $("liveAlertNote");
    const badge = $("liveAlertBadge");
    const dot = $("liveAlertDot");
    try {
      const response = await fetch("/api/wazuh/alerts?minutes=60&limit=40", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || `Wazuh request failed (${response.status})`);
      const items = Array.isArray(data.items) ? data.items : [];
      renderAlerts(items);
      if (title) title.textContent = items.length ? "Receiving real Wazuh detections" : "Wazuh connected — waiting for a FAST detection";
      if (note) note.textContent = items.length ? `Newest alert: ${formatTime(items[0].timestamp)} · ${items[0].attack_type}` : `No rules 100200 / 100211 / 100221 in the last ${data.window_minutes || 60} minutes.`;
      if (badge) { badge.textContent = "WAZUH LIVE"; badge.className = "live-badge ok"; }
      if (dot) dot.className = "status-dot good";
    } catch (error) {
      renderAlerts([]);
      if (title) title.textContent = "Live Wazuh data unavailable";
      if (note) note.textContent = error.message;
      if (badge) { badge.textContent = "UNAVAILABLE"; badge.className = "live-badge bad"; }
      if (dot) dot.className = "status-dot bad";
    }
  }

  function redesignArchitecture() {
    const view = $("view-architecture");
    if (!view) return;
    view.innerHTML = `
      <div class="section-head">
        <div><h2>FAST Platform Architecture</h2><p>A scalable security platform: Wazuh provides the active SIEM core, TALON is an integrated threat-intelligence module, and future security solutions can plug into the same platform layer.</p></div>
        <div class="section-actions"><button class="btn" id="refreshAssets">Refresh Assets</button></div>
      </div>
      <div class="fast-platform-shell">
        <div class="platform-core-head">
          <div><div class="platform-core-title">FAST · Unified Security Platform</div><div class="platform-core-sub">One operational layer for security telemetry, intelligence and integrations. Current functionality is clearly separated from planned integrations.</div></div>
          <span class="platform-state">Platform Active</span>
        </div>
        <div class="module-grid">
          <div class="module-card active"><div class="module-label">Core security component</div><div class="module-name">SIEM / Wazuh</div><div class="module-desc">Agent inventory, endpoint telemetry, rules, alert generation, indexing and Threat Hunting.</div><span class="module-state">Active</span></div>
          <div class="module-card active"><div class="module-label">FAST module</div><div class="module-name">TALON</div><div class="module-desc">OSINT threat feeds, normalization, deduplication, confidence scoring and Wazuh IOC integration.</div><span class="module-state">Active</span></div>
          <div class="module-card future"><div class="module-label">Future integration</div><div class="module-name">SOAR</div><div class="module-desc">Planned orchestration and automated response integration. No fake automation is exposed today.</div><span class="module-state">Coming Soon</span></div>
          <div class="module-card future"><div class="module-label">Future integration</div><div class="module-name">PAM</div><div class="module-desc">Planned privileged-access visibility and control integration.</div><span class="module-state">Coming Soon</span></div>
          <div class="module-card future"><div class="module-label">Future integration</div><div class="module-name">EPM</div><div class="module-desc">Planned endpoint privilege management integration.</div><span class="module-state">Coming Soon</span></div>
          <div class="module-card future"><div class="module-label">Future integration</div><div class="module-name">DLP</div><div class="module-desc">Planned data-loss prevention telemetry and policy integration.</div><span class="module-state">Coming Soon</span></div>
        </div>
        <div class="arch-band">
          <div class="flow-node"><div><div class="flow-step">Inputs</div><div class="flow-title">Endpoints & Threat Feeds</div><div class="flow-desc">Wazuh agents provide endpoint telemetry while TALON ingests external intelligence.</div></div></div>
          <div class="flow-arrow">→</div>
          <div class="flow-node core"><div><div class="flow-step">Platform Core</div><div class="flow-title">FAST</div><div class="flow-desc">Unifies security visibility and integrations without pretending unfinished modules are operational.</div></div></div>
          <div class="flow-arrow">→</div>
          <div class="flow-node"><div><div class="flow-step">Security Operations</div><div class="flow-title">Detection & Expansion</div><div class="flow-desc">Current Wazuh detections plus a path for SOAR, PAM, EPM and DLP integrations.</div></div></div>
        </div>
      </div>
      <div class="card table-card" style="margin-top:16px">
        <div class="card-head" style="padding:18px 18px 0">
          <div><div class="card-kicker">Wazuh server API</div><div class="card-title">Asset Catalog</div></div>
          <div class="asset-summary"><span class="summary-chip"><strong id="assetTotal">0</strong> assets</span><span class="summary-chip"><strong id="assetActive">0</strong> active</span><span class="live-badge" id="assetSourceBadge">LIVE</span></div>
        </div>
        <div class="table-scroll">
          <table id="assetCatalogTable"><thead><tr><th>Agent ID</th><th>Hostname</th><th>OS</th><th>IP</th><th>Status</th><th>Wazuh Version</th><th>Last Keepalive</th></tr></thead><tbody id="assetCatalogBody"></tbody></table>
          <div class="platform-empty" id="assetCatalogEmpty">No Wazuh agents returned.</div>
        </div>
      </div>`;
    $("refreshAssets")?.addEventListener("click", loadAssets);
  }

  function renderAssets(items) {
    const body = $("assetCatalogBody");
    const empty = $("assetCatalogEmpty");
    if (!body) return;
    body.textContent = "";
    items.forEach((asset) => {
      const tr = document.createElement("tr");
      const fields = [
        asset.id || "—",
        asset.hostname || "Unknown",
        [asset.os, asset.os_version].filter(Boolean).join(" ") || "Unknown",
        asset.ip || "Unknown",
        asset.status || "unknown",
        asset.wazuh_version || "—",
        formatTime(asset.last_keepalive),
      ];
      fields.forEach((value, index) => {
        const td = document.createElement("td");
        if ([0, 3, 5, 6].includes(index)) td.className = "mono";
        if (index === 4) {
          const status = document.createElement("span");
          status.className = `asset-status ${String(asset.status || "unknown").toLowerCase()}`;
          status.textContent = escText(value);
          td.appendChild(status);
        } else {
          td.textContent = escText(value);
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    if (empty) empty.style.display = items.length ? "none" : "block";
    const active = items.filter((item) => String(item.status).toLowerCase() === "active").length;
    if ($("assetTotal")) $("assetTotal").textContent = String(items.length);
    if ($("assetActive")) $("assetActive").textContent = String(active);
  }

  async function loadAssets() {
    if (!$("assetCatalogBody")) return;
    const badge = $("assetSourceBadge");
    try {
      const response = await fetch("/api/wazuh/assets", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || `Wazuh request failed (${response.status})`);
      const items = Array.isArray(data.items) ? data.items : [];
      renderAssets(items);
      if (badge) { badge.textContent = "WAZUH API LIVE"; badge.className = "live-badge ok"; badge.title = data.source || "wazuh-server-api"; }
    } catch (error) {
      renderAssets([]);
      const empty = $("assetCatalogEmpty");
      if (empty) { empty.style.display = "block"; empty.textContent = `Asset Catalog unavailable: ${error.message}`; }
      if (badge) { badge.textContent = "UNAVAILABLE"; badge.className = "live-badge bad"; }
    }
  }

  function hookArchitectureRefresh() {
    const button = document.querySelector('[data-view="architecture"]');
    if (button) button.addEventListener("click", () => setTimeout(loadAssets, 0));
  }

  function startLiveRefresh() {
    window.setInterval(() => {
      if ($("view-simulation")?.classList.contains("active")) loadLiveAlerts();
    }, 8000);
  }

  removeThreatFeedsNav();
  installSimulationNav();
  installSimulationView();
  redesignArchitecture();
  hookArchitectureRefresh();
  startLiveRefresh();
})();