/* COMMANDsentry — dashboard (v3 apex-as-asset schema with subdomain drill-down)
   Vanilla JS, no framework.
   ──────────────────────────────────────────────────────────────────────── */

(() => {
  "use strict";

  const DATA_DIR = "./data";
  const MANIFEST = `${DATA_DIR}/_manifest.json`;

  const state = {
    assets: [],
    filterText: "",
    filterTag: "",
    filterOwner: "",
    activeView: "inventory",
    activeAsset: null,        // currently-open asset id
    activeSub: null,          // currently-expanded subdomain name within drawer
  };

  document.addEventListener("DOMContentLoaded", async () => {
    bindUI();
    try { await loadAll(); }
    catch (e) { return showLoadError(e); }
    setView(state.activeView);
    render();
    startGlobalScanWatch();
  });

  // ─── Global scan-status watcher (top-bar pill) ───────────
  // Polls every 20s regardless of modal state. Shows a pill in the top bar
  // when any scan is running, hides when idle. If a scan completes, refreshes
  // the dashboard data after a 60s grace period (allows deploy to finish).
  let globalScanTimer = null;
  let lastGlobalRunId = null;
  let lastGlobalStatus = null;

  function startGlobalScanWatch() {
    pollGlobalScan();
    globalScanTimer = setInterval(pollGlobalScan, 20000);
  }

  async function pollGlobalScan() {
    try {
      const r = await fetch("/api/scan-status", { cache: "no-store" });
      if (!r.ok) return hideGlobalPill();
      const data = await r.json();
      if (!data.ok) return hideGlobalPill();

      const pill = document.getElementById("global-scan-pill");
      if (!pill) return;

      // If status is queued or in_progress → show compact "scanning" pill with ETA
      if (data.status === "queued" || data.status === "in_progress") {
        const phase = data.status === "queued" ? "queued" : abbreviateStep(data.job?.current_step || "running");
        const etaTxt = formatEtaShort(data);  // "~6m left" / "running long" / ""
        pill.hidden = false;
        pill.className = "global-scan-pill running";
        pill.innerHTML = `<span class="g-dot"></span><strong>${escapeHtml(formatElapsed(data.elapsed_seconds))}</strong>&nbsp;·&nbsp;${escapeHtml(phase)}${etaTxt ? `&nbsp;·&nbsp;<span class="g-eta">${escapeHtml(etaTxt)}</span>` : ""}`;
        pill.title = `Scan in progress · run #${data.run_id} · ${data.event} · current step: ${data.job?.current_step || "—"}${data.historical_avg_seconds ? ` · avg run: ${formatElapsed(data.historical_avg_seconds)}` : ""}`;
        lastGlobalRunId = data.run_id;
        lastGlobalStatus = data.status;
      } else if (data.status === "completed") {
        // If we previously saw it running and now it's done → flash success briefly + auto-refresh
        if (lastGlobalRunId === data.run_id && lastGlobalStatus !== "completed") {
          pill.hidden = false;
          pill.className = "global-scan-pill done";
          pill.innerHTML = `<span class="g-dot"></span>scan complete · refreshing…`;
          pill.title = "Dashboard will reload shortly to pick up the new data";
          setTimeout(() => {
            loadAll().then(render).catch(() => {});
            hideGlobalPill();
          }, 60000);
        } else {
          hideGlobalPill();
        }
        lastGlobalStatus = data.status;
      } else {
        hideGlobalPill();
      }
    } catch {
      hideGlobalPill();
    }
  }

  function hideGlobalPill() {
    const pill = document.getElementById("global-scan-pill");
    if (pill) pill.hidden = true;
  }

  // ─── data loading ────────────────────────────────────────
  async function loadAll() {
    let manifest;
    try {
      const r = await fetch(MANIFEST, { cache: "no-store" });
      if (!r.ok) throw new Error(`manifest ${r.status}`);
      manifest = await r.json();
    } catch (e) {
      throw new Error(`Couldn't load ${MANIFEST}: ${e.message}.`);
    }
    const ids = manifest.assets || [];
    if (!ids.length) throw new Error("Manifest has no assets.");
    const results = await Promise.all(
      ids.map(async (id) => {
        try {
          const r = await fetch(`${DATA_DIR}/${id}.json`, { cache: "no-store" });
          if (!r.ok) return null;
          return await r.json();
        } catch { return null; }
      })
    );
    state.assets = results.filter(Boolean).filter((a) => a.schema_version === "3.0");
  }

  function showLoadError(e) {
    const el = document.getElementById("view-loading");
    if (el) el.innerHTML = `<div class="empty"><strong>${escapeHtml(e.message)}</strong></div>`;
  }

  // ─── ui binding ──────────────────────────────────────────
  function bindUI() {
    document.querySelectorAll(".tab").forEach((tab) => {
      tab.addEventListener("click", () => setView(tab.dataset.view));
    });
    document.getElementById("refresh-btn").addEventListener("click", async () => {
      await loadAll().catch(showLoadError);
      render();
    });
    document.getElementById("filter-input").addEventListener("input", (e) => {
      state.filterText = e.target.value.toLowerCase();
      renderInventory();
    });
    document.getElementById("filter-tag").addEventListener("change", (e) => {
      state.filterTag = e.target.value; renderInventory();
    });
    document.getElementById("filter-owner").addEventListener("change", (e) => {
      state.filterOwner = e.target.value; renderInventory();
    });
    document.getElementById("drawer-close").addEventListener("click", closeDrawer);
    document.querySelector(".drawer-backdrop").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { closeDrawer(); closeAddModal(); }
    });
    // Add-target modal (unchanged)
    document.getElementById("add-target-btn").addEventListener("click", openAddModal);
    document.getElementById("add-modal-close").addEventListener("click", closeAddModal);
    document.getElementById("add-cancel-btn").addEventListener("click", closeAddModal);
    document.querySelector("#add-modal .modal-backdrop").addEventListener("click", closeAddModal);
    document.getElementById("add-target-form").addEventListener("submit", handleAddSubmit);
    document.querySelectorAll("input[name=\"type\"]").forEach((r) => r.addEventListener("change", updateTypeHelp));
    document.getElementById("t-value").addEventListener("input", autofillId);
    const idInput = document.getElementById("t-id");
    if (idInput) idInput.addEventListener("input", () => { idInput.dataset.touched = "true"; });
  }

  function setView(name) {
    state.activeView = name;
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    document.getElementById(`view-${name}`)?.classList.add("active");
    render();
  }

  // ─── rendering ───────────────────────────────────────────
  function render() {
    renderTopbar();
    renderInventory();
    renderChanged();
    populateFilters();
  }

  function renderTopbar() {
    const el = document.getElementById("last-scan-summary");
    if (!state.assets.length) { el.textContent = "no data"; return; }
    const newest = state.assets.map((a) => a.scan?.completed_at).filter(Boolean).sort().pop();
    const totalSubs = state.assets.reduce((n, a) => n + (a.summary?.subdomain_count || 0), 0);
    el.textContent = `${state.assets.length} domain${state.assets.length === 1 ? "" : "s"} · ${totalSubs} subdomain${totalSubs === 1 ? "" : "s"} · last scan ${formatRelTime(newest)}`;
  }

  function populateFilters() {
    const tagSel = document.getElementById("filter-tag");
    const ownerSel = document.getElementById("filter-owner");
    const tags = new Set(); const owners = new Set();
    state.assets.forEach((a) => {
      (a.asset?.tags || []).forEach((t) => tags.add(t));
      if (a.asset?.owner) owners.add(a.asset.owner);
    });
    fillSelect(tagSel, [...tags].sort(), "All tags");
    fillSelect(ownerSel, [...owners].sort(), "All owners");
  }

  function fillSelect(sel, items, defaultLabel) {
    const cur = sel.value;
    sel.innerHTML = `<option value="">${defaultLabel}</option>` +
      items.map((v) => `<option value="${escapeAttr(v)}">${escapeHtml(v)}</option>`).join("");
    if (items.includes(cur)) sel.value = cur;
  }

  // ─── inventory cards (apex-level summary) ────────────────
  function renderInventory() {
    const grid = document.getElementById("inventory-grid");
    const filtered = state.assets.filter(matchesFilter);
    if (!filtered.length) {
      grid.innerHTML = `<div class="empty">${state.assets.length ? "No matches." : "No assets yet."}</div>`;
      return;
    }
    grid.innerHTML = filtered.map(renderAssetCard).join("");
    grid.querySelectorAll(".asset-card").forEach((card, i) => {
      card.style.animationDelay = `${i * 60}ms`;
      card.addEventListener("click", () => openDrawer(card.dataset.id));
    });
    setTimeout(() => animateCounters(grid), 50);
  }

  function matchesFilter(a) {
    if (state.filterTag && !(a.asset?.tags || []).includes(state.filterTag)) return false;
    if (state.filterOwner && a.asset?.owner !== state.filterOwner) return false;
    if (state.filterText) {
      const subs = a.subdomains || [];
      const hay = [
        a.asset?.value, a.asset?.id, a.asset?.owner,
        ...(a.asset?.tags || []),
        ...subs.map((s) => s.name),
        ...subs.flatMap((s) => (s.fingerprint?.tech || []).map((t) => t.name)),
        ...subs.flatMap((s) => (s.hosts || []).map((h) => h.asn_org)),
      ].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(state.filterText)) return false;
    }
    return true;
  }

  function renderAssetCard(a) {
    const sm = a.summary || {};
    const subCount = sm.live_subdomain_count || 0;
    const hostCount = sm.host_count || 0;
    const svcCount = sm.service_count || 0;
    const topOrg = sm.top_hosting_org;
    const platforms = sm.platforms || [];
    const live = a.subdomains?.some((s) => s.reachability?.live);

    return `
      <div class="asset-card asset-card-v3" data-id="${escapeAttr(a.asset?.id || "")}">
        <div class="asset-card-head">
          <div class="asset-card-title-block">
            <div class="status-dot ${live ? "live" : "down"}" aria-label="${live ? "live" : "offline"}"></div>
            <div class="asset-card-title">${escapeHtml(a.asset?.value || a.asset?.id || "?")}</div>
          </div>
          <span class="asset-card-type">${escapeHtml((a.asset?.type || "").toUpperCase())}</span>
        </div>

        <div class="asset-stats">
          <div class="stat"><span class="stat-num" data-count="${subCount}">0</span><span class="stat-label">sub${subCount === 1 ? "" : "s"}</span></div>
          <div class="stat"><span class="stat-num" data-count="${hostCount}">0</span><span class="stat-label">host${hostCount === 1 ? "" : "s"}</span></div>
          <div class="stat"><span class="stat-num" data-count="${svcCount}">0</span><span class="stat-label">service${svcCount === 1 ? "" : "s"}</span></div>
        </div>

        <div class="asset-card-row">
          ${platforms.slice(0, 2).map((p) => `<span class="platform-pill">${escapeHtml(p)}</span>`).join("")}
        </div>

        ${(a.asset?.tags || []).length ? `<div class="tag-row">${a.asset.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}

        <div class="asset-card-footer">
          <span class="card-drill-hint">${subCount} subdomain${subCount === 1 ? "" : "s"} →</span>
        </div>
      </div>
    `;
  }

  function hostingClassFor(org) {
    if (!org) return "";
    const o = org.toLowerCase();
    if (o.includes("cloudflare"))  return "h-cloudflare";
    if (o.includes("amazon") || o.includes("aws"))    return "h-aws";
    if (o.includes("microsoft") || o.includes("azure")) return "h-azure";
    if (o.includes("google"))      return "h-google";
    if (o.includes("pressable"))   return "h-pressable";
    if (o.includes("wp engine"))   return "h-wpengine";
    if (o.includes("godaddy"))     return "h-godaddy";
    if (o.includes("digitalocean"))return "h-do";
    if (o.includes("sci"))         return "h-sci";
    // Eyeball networks / ISPs — these show up for office uplinks, not hosting
    if (o.includes("cablevision") || o.includes("charter") || o.includes("spectrum") ||
        o.includes("verizon") || o.includes("comcast") || o.includes("optimum") ||
        o.includes("at&t") || o.includes("att inc") || o.includes("cox") ||
        o.includes("centurylink") || o.includes("lumen")) {
      return "h-isp";
    }
    return "h-other";
  }

  function animateCounters(scope) {
    scope.querySelectorAll("[data-count]").forEach((el) => {
      const target = parseInt(el.dataset.count, 10);
      if (!Number.isFinite(target) || target === 0) { el.textContent = "0"; return; }
      const duration = 600;
      const start = performance.now();
      const step = (now) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 3);
        el.textContent = Math.round(target * eased);
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  }

  // ─── what changed feed (v3 — subdomain-aware) ────────────
  function renderChanged() {
    const feed = document.getElementById("changed-feed");
    const events = [];
    state.assets.forEach((a) => {
      const aname = a.asset?.value || a.asset?.id;
      const d = a.deltas || {};
      (d.added?.subdomains   || []).forEach((s) => events.push(["added", "+", `New subdomain discovered: ${s}`, aname]));
      (d.added?.hosts        || []).forEach((h) => events.push(["added", "+", `New host on ${h.subdomain}: ${h.ip}`, aname]));
      (d.added?.services     || []).forEach((s) => events.push(["added", "+", `New service on ${s.subdomain}: ${s.port}/${s.protocol}`, aname]));
      (d.removed?.subdomains || []).forEach((s) => events.push(["removed", "−", `Subdomain went away: ${s}`, aname]));
      (d.removed?.hosts      || []).forEach((h) => events.push(["removed", "−", `Host removed from ${h.subdomain}: ${h.ip}`, aname]));
      (d.removed?.services   || []).forEach((s) => events.push(["removed", "−", `Service closed on ${s.subdomain}: ${s.port}/${s.protocol}`, aname]));
      (d.changed?.fingerprint || []).forEach((t) => events.push(["changed", "Δ", `${t.subdomain}: ${t.name} ${t.from || "?"} → ${t.to || "?"}`, aname]));
    });
    if (!events.length) {
      feed.innerHTML = `<div class="empty">No surface changes detected since previous scans.</div>`;
      return;
    }
    feed.innerHTML = events.map(([type, icon, text, asset]) => `
      <div class="feed-row ${type}">
        <span class="feed-icon">${escapeHtml(icon)}</span>
        <div style="flex:1;">
          <div>${escapeHtml(text)}</div>
          <div class="feed-asset">${escapeHtml(asset)}</div>
        </div>
      </div>
    `).join("");
  }

  // ─── drawer (v3 — apex overview + subdomain table) ──────
  function openDrawer(id) {
    const a = state.assets.find((x) => x.asset?.id === id);
    if (!a) return;
    state.activeAsset = id;
    state.activeSub = null;

    document.getElementById("drawer-title").textContent = a.asset?.value || a.asset?.id;
    document.getElementById("drawer-body").innerHTML = renderApexOverview(a);
    bindDrawerInteractions(a);

    const drawer = document.getElementById("drawer");
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    setTimeout(() => animateCounters(document.getElementById("drawer-body")), 50);
  }

  function closeDrawer() {
    const d = document.getElementById("drawer");
    d.classList.remove("open"); d.setAttribute("aria-hidden", "true");
    state.activeAsset = null; state.activeSub = null;
  }

  function bindDrawerInteractions(asset) {
    document.querySelectorAll(".sub-row").forEach((row) => {
      row.addEventListener("click", () => {
        const subName = row.dataset.sub;
        showSubDetail(asset, subName);
      });
    });
    document.querySelector(".back-to-overview")?.addEventListener("click", () => {
      state.activeSub = null;
      const a = state.assets.find((x) => x.asset?.id === state.activeAsset);
      document.getElementById("drawer-body").innerHTML = renderApexOverview(a);
      bindDrawerInteractions(a);
      setTimeout(() => animateCounters(document.getElementById("drawer-body")), 50);
    });
  }

  function showSubDetail(asset, subName) {
    state.activeSub = subName;
    const sub = asset.subdomains.find((s) => s.name === subName);
    if (!sub) return;
    document.getElementById("drawer-body").innerHTML = renderSubDetail(asset, sub);
    bindDrawerInteractions(asset);
    document.getElementById("drawer-body").scrollTop = 0;
    setTimeout(() => animateCounters(document.getElementById("drawer-body")), 50);
  }

  // ─── apex-level overview ────────────────────────────────
  function renderApexOverview(a) {
    const sm = a.summary || {};
    const live = a.subdomains?.some((s) => s.reachability?.live);
    const certDays = sm.newest_cert_expiry_days;
    const certBadge = certDays === null || certDays === undefined ? null
      : certDays < 7 ? { label: `Cert expires in ${certDays}d`, cls: "v-bad" }
      : certDays < 30 ? { label: `Cert expires in ${certDays}d`, cls: "v-warn" }
      : { label: `Nearest cert ${certDays}d`, cls: "v-good" };

    return `
      <div class="verdict-strip">
        <div class="verdict-row">
          <div class="verdict-pill ${live ? "v-good" : "v-bad"}">
            <span class="status-dot ${live ? "live" : "down"}"></span>
            ${live ? "Live surface" : "All offline"}
          </div>
          ${certBadge ? `<div class="verdict-pill ${certBadge.cls}"><span class="v-icon">🔒</span>${escapeHtml(certBadge.label)}</div>` : ""}
          ${(sm.platforms || []).map((p) => `<div class="verdict-pill v-info platform-pill">${escapeHtml(p)}</div>`).join("")}
        </div>
        <div class="verdict-stats">
          <div class="stat-big"><div class="stat-num" data-count="${sm.live_subdomain_count || 0}">0</div><div class="stat-label">${(sm.live_subdomain_count || 0) === 1 ? "subdomain" : "subdomains"}</div></div>
          <div class="stat-big"><div class="stat-num" data-count="${sm.host_count || 0}">0</div><div class="stat-label">${(sm.host_count || 0) === 1 ? "host" : "hosts"}</div></div>
          <div class="stat-big"><div class="stat-num" data-count="${sm.service_count || 0}">0</div><div class="stat-label">${(sm.service_count || 0) === 1 ? "service" : "services"}</div></div>
        </div>
      </div>

      ${renderSubdomainsTable(a)}
      ${renderRegistrationSection(a)}
      ${renderProvenanceSection(a)}
    `;
  }

  function renderSubdomainsTable(a) {
    const subs = a.subdomains || [];
    if (!subs.length) return section("Subdomains", "<div class='muted'>No subdomains.</div>");
    const rows = subs.map((s) => {
      const live = s.reachability?.live;
      const hostCount = (s.hosts || []).length;
      const svcCount = (s.services || []).length;
      const waf = s.waf?.detected ? s.waf.vendor : null;
      const platform = s.fingerprint?.platform_label;
      const certDays = s.services?.find((x) => x.cert?.days_to_expiry !== undefined)?.cert?.days_to_expiry;
      return `
        <tr class="sub-row" data-sub="${escapeAttr(s.name)}">
          <td>
            <div class="sub-name">
              <span class="status-dot ${live ? "live" : "down"}"></span>
              <span class="td-mono">${escapeHtml(s.name)}</span>
              ${s.is_root ? "<span class='sub-root-badge'>root</span>" : ""}
            </div>
            ${platform ? `<div class="sub-platform">${escapeHtml(platform)}</div>` : ""}
          </td>
          <td>${hostCount > 0 ? `<span class="kv-num">${hostCount}</span>` : "<span class='muted'>0</span>"}</td>
          <td>${svcCount > 0 ? `<span class="kv-num">${svcCount}</span>` : "<span class='muted'>0</span>"}</td>
          <td>${waf ? `<span class="waf-pill"><span class="waf-pill-icon">⛨</span>${escapeHtml(waf)}</span>` : "<span class='muted'>—</span>"}</td>
          <td>${typeof certDays === "number" ? renderCertDaysBadge(certDays) : "<span class='muted'>—</span>"}</td>
          <td class="td-arrow">→</td>
        </tr>`;
    }).join("");
    return section(`Subdomains (${subs.length})`, `
      <table class="data-table sub-table">
        <thead><tr><th>Name</th><th>Hosts</th><th>Svcs</th><th>WAF</th><th>Cert</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="sub-table-hint">Click any row to drill into that subdomain</div>
    `);
  }

  function renderCertDaysBadge(days) {
    const cls = days < 7 ? "cert-bad" : days < 30 ? "cert-warn" : "cert-good";
    return `<span class="cert-days-badge ${cls}">${days}d</span>`;
  }

  // ─── per-subdomain detail view ──────────────────────────
  function renderSubDetail(asset, sub) {
    const live = sub.reachability?.live;
    const status = sub.reachability?.http_status;
    const wafVendor = sub.waf?.detected ? sub.waf.vendor : null;
    const topOrg = sub.hosts?.[0]?.asn_org;
    const certNearest = nearestCertDays(sub.services || []);
    const hostCount = (sub.hosts || []).length;
    const svcCount = (sub.services || []).length;

    return `
      <div class="sub-detail-header">
        <button class="back-to-overview">← Back to ${escapeHtml(asset.asset.value)}</button>
        <div class="sub-detail-name">
          <span class="status-dot ${live ? "live" : "down"}"></span>
          <span class="td-mono">${escapeHtml(sub.name)}</span>
          ${sub.is_root ? "<span class='sub-root-badge'>root</span>" : ""}
        </div>
        ${sub.reachability?.title ? `<div class="sub-detail-title">${escapeHtml(sub.reachability.title)}</div>` : ""}
      </div>

      <div class="verdict-strip">
        <div class="verdict-row">
          <div class="verdict-pill ${live ? "v-good" : "v-bad"}">
            <span class="status-dot ${live ? "live" : "down"}"></span>
            ${live ? `Live · HTTP ${status || "?"}` : "Offline"}
          </div>
          ${wafVendor ? `<div class="verdict-pill v-info waf-pill"><span class="waf-pill-icon">⛨</span>${escapeHtml(wafVendor)}</div>` : ""}
          ${certNearest !== null ? `<div class="verdict-pill ${certNearest < 7 ? "v-bad" : certNearest < 30 ? "v-warn" : "v-good"}"><span class="v-icon">🔒</span>Cert ${certNearest}d</div>` : ""}
          ${sub.fingerprint?.platform_label ? `<div class="verdict-pill v-info platform-pill">${escapeHtml(sub.fingerprint.platform_label)}</div>` : ""}
        </div>
        <div class="verdict-stats">
          <div class="stat-big"><div class="stat-num" data-count="${hostCount}">0</div><div class="stat-label">${hostCount === 1 ? "host" : "hosts"}</div></div>
          <div class="stat-big"><div class="stat-num" data-count="${svcCount}">0</div><div class="stat-label">${svcCount === 1 ? "service" : "services"}</div></div>
        </div>
      </div>

      ${renderHostsSection(sub)}
      ${renderServicesSection(sub)}
      ${renderDnsSection(sub)}
      ${renderFingerprintSection(sub)}
    `;
  }

  function nearestCertDays(services) {
    let nearest = null;
    for (const s of services) {
      const d = s.cert?.days_to_expiry;
      if (typeof d === "number" && (nearest === null || d < nearest)) nearest = d;
    }
    return nearest;
  }

  function renderHostsSection(sub) {
    const hosts = sub.hosts || [];
    if (!hosts.length) return section("Hosts", "<div class='muted'>No IP attribution available.</div>");
    const rows = hosts.map((h) => {
      const geo = [h.city, h.region, h.country].filter(Boolean).join(", ");
      const cls = hostingClassFor(h.asn_org);
      return `
        <tr>
          <td class="td-mono">${escapeHtml(h.ip || "")}</td>
          <td>${h.asn_org ? `<span class="hosting-pill ${cls}">${escapeHtml(h.asn_org)}</span>` : "<span class='muted'>—</span>"}</td>
          <td class="td-mono muted">${escapeHtml(h.asn || "—")}</td>
          <td>${escapeHtml(geo) || "<span class='muted'>—</span>"}</td>
          <td class="td-mono muted">${escapeHtml(h.reverse_dns || "—")}</td>
        </tr>`;
    }).join("");
    return section("Hosts", `
      <table class="data-table">
        <thead><tr><th>IP</th><th>Hosting</th><th>ASN</th><th>Location</th><th>Reverse DNS</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `);
  }

  function renderServicesSection(sub) {
    const services = sub.services || [];
    if (!services.length) return section("Services", "<div class='muted'>No services detected.</div>");
    const rows = services.map((s) => `
      <tr>
        <td class="td-mono">${escapeHtml(s.ip || "")}</td>
        <td><span class="port-cell">${s.port}<span class="port-proto">/${s.protocol}</span></span></td>
        <td>${renderServiceBadge(s.service, s.tls)}</td>
        <td class="td-mono muted">${escapeHtml(s.banner || "—")}</td>
        <td>${renderCertCell(s.cert)}</td>
      </tr>`).join("");
    return section("Services", `
      <table class="data-table">
        <thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Banner</th><th>TLS / Cert</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `);
  }

  function renderServiceBadge(name, tls) {
    if (!name) return "<span class='muted'>—</span>";
    const lookup = {
      http: { icon: "▤", cls: "svc-web" },        https: { icon: "▥", cls: "svc-web-tls" },
      "http-alt": { icon: "▤", cls: "svc-web" },   "https-alt": { icon: "▥", cls: "svc-web-tls" },
      ssh: { icon: "⌨", cls: "svc-shell" },        ftp: { icon: "⇅", cls: "svc-file" },
      sftp: { icon: "⇅", cls: "svc-file" },        smtp: { icon: "✉", cls: "svc-mail" },
      smtps: { icon: "✉", cls: "svc-mail" },       submission: { icon: "✉", cls: "svc-mail" },
      imap: { icon: "✉", cls: "svc-mail" },        imaps: { icon: "✉", cls: "svc-mail" },
      pop3: { icon: "✉", cls: "svc-mail" },        pop3s: { icon: "✉", cls: "svc-mail" },
      dns: { icon: "❂", cls: "svc-net" },          mysql: { icon: "▦", cls: "svc-db" },
      postgres: { icon: "▦", cls: "svc-db" },      mssql: { icon: "▦", cls: "svc-db" },
      mongodb: { icon: "▦", cls: "svc-db" },       redis: { icon: "▦", cls: "svc-db" },
      elasticsearch: { icon: "▦", cls: "svc-db" }, rdp: { icon: "▣", cls: "svc-shell" },
      vnc: { icon: "▣", cls: "svc-shell" },        telnet: { icon: "⌨", cls: "svc-shell" },
    };
    const meta = lookup[name] || { icon: "●", cls: "svc-unknown" };
    return `<span class="service-badge ${meta.cls}"><span class="svc-icon">${meta.icon}</span>${escapeHtml(name)}${tls ? "<span class='svc-tls'>TLS</span>" : ""}</span>`;
  }

  function renderCertCell(cert) {
    if (!cert || !cert.issuer && !cert.not_after) return "<span class='muted'>—</span>";
    const days = cert.days_to_expiry;
    const cls = days === undefined || days === null ? ""
      : days < 7  ? "cert-bad"
      : days < 30 ? "cert-warn"
      : "cert-good";
    return `
      <div class="cert-cell ${cls}">
        <div class="cert-issuer">${escapeHtml(cert.issuer || "?")}</div>
        ${typeof days === "number" ? `<div class="cert-days">${days}d to expiry</div>` : ""}
      </div>
    `;
  }

  function renderDnsSection(sub) {
    const d = sub.dns || {};
    if (!d.a?.length && !d.ns?.length) return "";
    const rows = [
      ["A", (d.a || []).join(", ")],
      ["AAAA", (d.aaaa || []).join(", ")],
      ["CNAME", d.cname],
      ["MX", (d.mx || []).map((m) => `${m.priority} ${m.host}`).join(", ")],
      ["NS", (d.ns || []).join(", ")],
      ["SPF", d.spf],
      ["DNSSEC", d.dnssec ? "enabled" : "disabled"],
    ].filter(([, v]) => v && v.length);
    return section("DNS", kvTable(rows));
  }

  function renderFingerprintSection(sub) {
    const fp = sub.fingerprint || {};
    if (!fp.tech?.length && !fp.server) return "";
    const grouped = groupTech(fp.tech || []);
    return section("Tech fingerprint", `
      ${fp.platform_label ? `<div class="platform-banner">${escapeHtml(fp.platform_label)}</div>` : ""}
      <div class="tech-groups">
        ${Object.entries(grouped).map(([cat, items]) => `
          <div class="tech-group">
            <div class="tech-group-label">${escapeHtml(prettyCategory(cat))}</div>
            <div class="tech-group-items">
              ${items.map((t) => `<span class="tech-chip">${escapeHtml(t.name)}${t.version ? `<span class="tech-chip-v">${escapeHtml(t.version)}</span>` : ""}</span>`).join("")}
            </div>
          </div>
        `).join("")}
      </div>
    `);
  }

  function groupTech(tech) {
    const order = ["hosting", "cdn", "webserver", "framework", "language", "database", "cms", "wp-plugin", "wp-theme", "frontend", "tracking", "transport", "security", "uncategorized"];
    const out = {};
    for (const t of tech) {
      const cat = (t.category || "uncategorized").toLowerCase();
      (out[cat] ||= []).push(t);
    }
    const sorted = {};
    for (const cat of order) if (out[cat]) sorted[cat] = out[cat];
    for (const cat of Object.keys(out)) if (!(cat in sorted)) sorted[cat] = out[cat];
    return sorted;
  }

  function prettyCategory(cat) {
    const map = {
      "wp-plugin": "WordPress plugins", "wp-theme": "WordPress themes",
      cms: "CMS", cdn: "CDN", webserver: "Web server", hosting: "Hosting",
      framework: "Framework", language: "Language / runtime", database: "Database",
      frontend: "Frontend libraries", tracking: "Analytics & tracking",
      transport: "Transport", security: "Security", uncategorized: "Other",
    };
    return map[cat] || cat;
  }

  function renderRegistrationSection(a) {
    const r = a.registration || {};
    if (!Object.keys(r).length) return "";
    return section("Domain registration (whois)", kvTable([
      ["Registrar", r.registrar],
      ["URL",       r.registrar_url],
      ["Created",   r.created],
      ["Updated",   r.updated],
      ["Expires",   r.expires],
      ["Status",    r.status],
    ]));
  }

  function renderProvenanceSection(a) {
    const s = a.scan || {};
    return section("Scan provenance", kvTable([
      ["Scan ID",    s.id],
      ["Started",    s.started_at],
      ["Completed",  s.completed_at],
      ["Duration",   `${s.duration_seconds || 0}s`],
      ["Engine",     s.engine_version],
      ["Origin",     s.scanner_origin],
      ["Tools run",  (s.tools_run || []).join(", ")],
    ]));
  }

  // ─── primitives ──────────────────────────────────────────
  function section(title, body) {
    return `<div class="drawer-section"><h4>${escapeHtml(title)}</h4>${body}</div>`;
  }
  function kvTable(rows) {
    return `<table class="kv-table">${rows
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join("")}</table>`;
  }
  function formatRelTime(iso) {
    if (!iso) return "—";
    const t = new Date(iso).getTime();
    if (isNaN(t)) return iso;
    const diff = Date.now() - t;
    const min = Math.floor(diff / 60000);
    if (min < 1) return "just now";
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    return `${Math.floor(hr / 24)}d ago`;
  }
  function escapeHtml(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function escapeAttr(s) { return escapeHtml(s); }

  // ─── add-target modal (unchanged) ────────────────────────
  function openAddModal() {
    const m = document.getElementById("add-modal");
    m.classList.add("open"); m.setAttribute("aria-hidden", "false");
    document.getElementById("add-form-feedback").hidden = true;
    document.getElementById("add-submit-btn").disabled = false;
    setTimeout(() => document.getElementById("t-value").focus(), 50);
  }
  function closeAddModal() {
    const m = document.getElementById("add-modal");
    m.classList.remove("open"); m.setAttribute("aria-hidden", "true");
  }
  function updateTypeHelp() {
    const t = document.querySelector("input[name=\"type\"]:checked")?.value || "apex";
    const help = document.getElementById("t-type-help");
    const valueInput = document.getElementById("t-value");
    const ph = {
      fqdn: { help: "Single hostname (legacy) — scans just this host", ph: "www.example.com" },
      apex: { help: "Apex domain (recommended) — enumerates subdomains, scans each", ph: "example.com" },
      ip:   { help: "Single IP — port + service discovery, no DNS context", ph: "198.51.100.42" },
      cidr: { help: "CIDR range — sweep for live hosts", ph: "198.51.100.0/29" },
    };
    help.innerHTML = ph[t].help;
    valueInput.placeholder = ph[t].ph;
    const idInput = document.getElementById("t-id");
    idInput.placeholder = (t === "ip") ? "host-198-51-100-42" : (t === "cidr") ? "range-198-51-100-0-29" : "example";
  }
  function autofillId() {
    const idInput = document.getElementById("t-id");
    if (idInput.dataset.touched === "true") return;
    const value = document.getElementById("t-value").value.trim().toLowerCase();
    const type  = document.querySelector("input[name=\"type\"]:checked")?.value || "apex";
    if (!value) { idInput.value = ""; return; }
    let id = (type === "fqdn" || type === "apex")
      ? value.replace(/^www\./, "").replace(/\..*$/, "").replace(/[^a-z0-9-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "")
      : value.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    idInput.value = id.slice(0, 64);
  }
  async function handleAddSubmit(e) {
    e.preventDefault();
    const submitBtn = document.getElementById("add-submit-btn");
    const feedback  = document.getElementById("add-form-feedback");
    feedback.hidden = false; feedback.className = "form-feedback info";
    feedback.textContent = "Submitting…"; submitBtn.disabled = true;

    const fd = new FormData(e.target);
    const payload = {
      id:    (fd.get("id") || "").trim(),
      type:  fd.get("type"),
      value: (fd.get("value") || "").trim().toLowerCase(),
      owner: (fd.get("owner") || "").trim(),
      tags:  (fd.get("tags") || "").split(",").map((t) => t.trim()).filter(Boolean),
      notes: (fd.get("notes") || "").trim(),
      scope_verified: !!fd.get("scope_verified"),
    };
    try {
      const r = await fetch("/api/add-target", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok && data.ok) {
        showAddSuccess(payload, data);
      } else {
        feedback.className = "form-feedback err";
        const detail = Array.isArray(data.details) ? data.details.join(" · ") : "";
        feedback.textContent = `Error: ${data.error || r.statusText}${detail ? " — " + detail : ""}`;
        submitBtn.disabled = false;
      }
    } catch (err) {
      feedback.className = "form-feedback err";
      feedback.textContent = "Network error: " + (err.message || "request failed");
      submitBtn.disabled = false;
    }
  }

  // Replace the form body with a live success state. Polls /api/scan-status
  // every 8 seconds while the modal is open and updates the timeline in real time.
  function showAddSuccess(payload, data) {
    const body = document.querySelector("#add-modal .modal-body");
    const sha = (data.commit?.sha || "").slice(0, 7);
    const commitUrl = data.commit?.url || "";
    const actionsUrl = "https://github.com/bklynhowster/commandsentry-asm/actions/workflows/asm-discover.yml";

    body.innerHTML = `
      <div class="add-success" data-target-id="${escapeAttr(payload.id)}">
        <div class="add-success-header">
          <div class="add-success-check">✓</div>
          <div class="add-success-title-block">
            <h3 class="add-success-title">Queued for scan</h3>
            <div class="add-success-target">
              <span class="td-mono">${escapeHtml(payload.value)}</span>
              <span class="asset-card-type">${escapeHtml(payload.type.toUpperCase())}</span>
            </div>
          </div>
        </div>

        <div class="live-status" id="live-status">
          <div class="live-status-row">
            <div class="live-status-pulse-block">
              <div class="live-status-pulse-dot pending"></div>
              <div class="live-status-headline" id="live-status-headline">Waiting for GitHub Actions to register the scan…</div>
            </div>
            <div class="live-status-elapsed" id="live-status-elapsed">—</div>
          </div>
          <div class="live-status-substep" id="live-status-substep">Polling every 8 seconds.</div>
          <div class="live-status-progress">
            <div class="live-status-progress-bar" id="live-status-progress-bar" style="width: 0%"></div>
          </div>
        </div>

        <div class="add-success-timeline" id="live-timeline">
          <div class="add-success-timeline-label">Pipeline steps</div>
          <div class="step-row step-done">
            <div class="step-icon">✓</div>
            <div class="step-body">
              <div class="step-label">Target committed to repo</div>
              <div class="step-detail">${sha ? `commit ${escapeHtml(sha)}` : ""}</div>
            </div>
          </div>
          <div class="step-row step-pending" id="step-rows-placeholder">
            <div class="step-icon">○</div>
            <div class="step-body">
              <div class="step-label">Loading workflow steps from GitHub…</div>
            </div>
          </div>
        </div>

        <div class="add-success-footnote">
          Safe to close — the scan keeps running on GitHub. The dashboard refreshes itself when it's done, and you'll get an email.
        </div>

        <div class="add-success-actions">
          ${commitUrl ? `<a href="${escapeAttr(commitUrl)}" target="_blank" rel="noopener" class="btn-link">View commit on GitHub →</a>` : ""}
          <a id="run-link" href="${escapeAttr(actionsUrl)}" target="_blank" rel="noopener" class="btn-link">Watch workflow run →</a>
          <div class="add-success-actions-buttons">
            <button type="button" id="add-another-btn" class="btn-ghost">Add another target</button>
            <button type="button" id="add-done-btn" class="btn-accent">Done</button>
          </div>
        </div>
      </div>
    `;

    document.getElementById("add-done-btn").addEventListener("click", () => {
      stopScanPolling();
      closeAddModal();
    });
    document.getElementById("add-another-btn").addEventListener("click", () => {
      stopScanPolling();
      restoreAddForm();
    });

    startScanPolling(payload.id);
  }

  // ─── Live scan polling ──────────────────────────────────
  let scanPollTimer = null;
  let scanPollAttempts = 0;
  const SCAN_POLL_INTERVAL_MS = 8000;

  function startScanPolling(targetId) {
    stopScanPolling();
    scanPollAttempts = 0;
    pollScanStatus(targetId);
    scanPollTimer = setInterval(() => pollScanStatus(targetId), SCAN_POLL_INTERVAL_MS);
  }

  function stopScanPolling() {
    if (scanPollTimer) {
      clearInterval(scanPollTimer);
      scanPollTimer = null;
    }
  }

  async function pollScanStatus(targetId) {
    scanPollAttempts++;
    try {
      const r = await fetch(`/api/scan-status?target_id=${encodeURIComponent(targetId)}`, { cache: "no-store" });
      if (!r.ok) {
        renderScanStatusError(`API ${r.status}`);
        return;
      }
      const data = await r.json();
      if (!data.ok) {
        renderScanStatusError(data.error || "unknown");
        return;
      }
      // Stop polling if the relevant run is older than ~1h (probably not our run)
      // or if status is "completed"
      renderScanStatus(data);
      if (data.status === "completed") {
        stopScanPolling();
        // Refresh dashboard data after a delay (allows deploy to complete)
        setTimeout(() => loadAll().then(render).catch(() => {}), 90000);
      }
      // Bail out if we've polled for >30 min with no completion (safety)
      if (scanPollAttempts > 250) stopScanPolling();
    } catch (e) {
      renderScanStatusError(e.message);
    }
  }

  function renderScanStatusError(msg) {
    const headline = document.getElementById("live-status-headline");
    const substep  = document.getElementById("live-status-substep");
    const dot      = document.querySelector(".live-status-pulse-dot");
    if (!headline) return;
    headline.textContent = "Couldn't reach scan-status API";
    substep.textContent  = String(msg).slice(0, 200);
    if (dot) dot.className = "live-status-pulse-dot error";
  }

  function renderScanStatus(data) {
    const headline = document.getElementById("live-status-headline");
    const substep  = document.getElementById("live-status-substep");
    const elapsed  = document.getElementById("live-status-elapsed");
    const dot      = document.querySelector(".live-status-pulse-dot");
    const progressBar = document.getElementById("live-status-progress-bar");
    const timeline = document.getElementById("live-timeline");
    const runLink  = document.getElementById("run-link");

    if (runLink && data.html_url) runLink.href = data.html_url;

    // Headline + dot state
    let phase = "pending", text = "";
    if (data.status === "queued") {
      phase = "pending";
      text  = "Queued — waiting for an available runner";
    } else if (data.status === "in_progress") {
      phase = "running";
      text  = data.job?.current_step ? `Running: ${data.job.current_step}` : "Running…";
    } else if (data.status === "completed") {
      if (data.conclusion === "success") {
        phase = "done";
        text  = data.mode === "scan" || data.mode === "single" || data.mode === "diff" || data.mode === "all"
          ? "Scan complete — dashboard will refresh shortly"
          : (data.mode === "skipped" ? "Workflow ran (skipped — no new targets to scan)" : "Workflow complete");
      } else {
        phase = "error";
        text  = `Workflow ${data.conclusion}`;
      }
    }
    headline.textContent = text;
    if (dot) dot.className = `live-status-pulse-dot ${phase}`;

    // Substep (extra context — appends ETA when we have historical data)
    const etaLabel = formatEtaLong(data);  // "ETA ~6m 30s" / "running long (~2m over avg)" / ""
    if (data.job) {
      const c = data.job.completed_steps;
      const t = data.job.total_steps;
      const stepInfo = `Step ${Math.min(c + (data.status === "in_progress" ? 1 : 0), t)} of ${t} · event: ${data.event} · run #${data.run_id}`;
      substep.textContent = etaLabel ? `${stepInfo} · ${etaLabel}` : stepInfo;
    } else {
      substep.textContent = "Polling every 8 seconds.";
    }

    // Elapsed clock
    elapsed.textContent = formatElapsed(data.elapsed_seconds);

    // Progress bar — use the larger of step-based and time-based progress, capped at 95%
    // until completion (so it can't fake 100% while still running). On success → 100%.
    const stepPct = data.job?.progress_pct ?? 0;
    const timePct = computeTimePct(data);
    let pct = Math.max(stepPct, timePct);
    if (data.status !== "completed") pct = Math.min(pct, 95);
    else if (data.conclusion === "success") pct = 100;
    if (progressBar) progressBar.style.width = `${pct}%`;

    // Step timeline — replace placeholder with real steps once we have them
    if (data.job?.step_timeline?.length) {
      const placeholder = document.getElementById("step-rows-placeholder");
      const stepsHtml = data.job.step_timeline.map((s) => {
        let state = "pending", icon = "○";
        if (s.status === "completed" && s.conclusion === "success") { state = "done"; icon = "✓"; }
        else if (s.status === "completed" && s.conclusion !== "success") { state = "error"; icon = "✗"; }
        else if (s.status === "in_progress") { state = "running"; icon = "●"; }
        else if (s.status === "queued") { state = "pending"; icon = "○"; }

        const detail = s.completed_at && s.started_at
          ? `${Math.max(0, Math.round((new Date(s.completed_at) - new Date(s.started_at)) / 1000))}s`
          : (s.status === "in_progress" ? "running" : "");

        return `
          <div class="step-row step-${state}">
            <div class="step-icon">${icon}</div>
            <div class="step-body">
              <div class="step-label">${escapeHtml(s.name)}</div>
              ${detail ? `<div class="step-detail">${escapeHtml(detail)}</div>` : ""}
            </div>
          </div>
        `;
      }).join("");

      // Replace placeholder section, keep the original "Target committed to repo" first row
      const firstRow = timeline.querySelector(".step-done");
      timeline.innerHTML = '<div class="add-success-timeline-label">Pipeline steps</div>';
      if (firstRow) timeline.appendChild(firstRow);
      timeline.insertAdjacentHTML("beforeend", stepsHtml);
    }
  }

  function formatElapsed(sec) {
    if (!sec || sec < 0) return "—";
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return m > 0 ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
  }

  // Compact step labels for the global pill so it fits in the top-bar
  function abbreviateStep(name) {
    if (!name) return "running";
    const n = name.toLowerCase();
    if (n.includes("install asm tool"))   return "installing tools";
    if (n.includes("install"))            return "installing";
    if (n.includes("set up"))             return "setting up";
    if (n.includes("checkout"))           return "checkout";
    if (n.includes("determine targets"))  return "planning";
    if (n.includes("run asm discovery"))  return "scanning";
    if (n.includes("sync dashboard"))     return "syncing data";
    if (n.includes("send email"))         return "alerting";
    if (n.includes("commit scan"))        return "committing";
    if (n.includes("trigger netlify"))    return "deploying";
    if (n.includes("summarize"))          return "summarizing";
    if (n.includes("verify"))             return "verifying";
    if (n.includes("cache"))              return "caching";
    return name.length > 24 ? name.slice(0, 22) + "…" : name;
  }

  // ─── ETA helpers (time-aware progress) ───────────────────
  // Compute time-based completion percentage from elapsed vs historical avg.
  // Returns 0 if no historical data yet.
  function computeTimePct(data) {
    const avg = data.historical_avg_seconds;
    const el  = data.elapsed_seconds;
    if (!avg || !el || avg <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round((el / avg) * 100)));
  }

  // Long-form ETA for the modal substep line.
  function formatEtaLong(data) {
    const avg = data.historical_avg_seconds;
    const el  = data.elapsed_seconds;
    if (data.status !== "in_progress" && data.status !== "queued") return "";
    if (!avg || !el) return "";
    const remaining = avg - el;
    if (remaining > 0) return `ETA ~${formatElapsed(remaining)} (avg ${formatElapsed(avg)})`;
    return `running long (~${formatElapsed(Math.abs(remaining))} over avg ${formatElapsed(avg)})`;
  }

  // Short-form ETA for the top-bar pill.
  function formatEtaShort(data) {
    const avg = data.historical_avg_seconds;
    const el  = data.elapsed_seconds;
    if (!avg || !el) return "";
    const remaining = avg - el;
    if (remaining > 0) return `~${formatElapsed(remaining)} left`;
    return "running long";
  }

  // Restore the original form into the modal body
  function restoreAddForm() {
    const body = document.querySelector("#add-modal .modal-body");
    body.innerHTML = ORIGINAL_ADD_FORM_HTML;
    // Re-bind everything because the form is fresh DOM
    document.getElementById("add-target-form").addEventListener("submit", handleAddSubmit);
    document.querySelectorAll("input[name=\"type\"]").forEach((r) => r.addEventListener("change", updateTypeHelp));
    document.getElementById("t-value").addEventListener("input", autofillId);
    const idInput = document.getElementById("t-id");
    if (idInput) idInput.addEventListener("input", () => { idInput.dataset.touched = "true"; });
    updateTypeHelp();
  }

  // Snapshot the original form HTML so we can restore it after a success
  let ORIGINAL_ADD_FORM_HTML = "";
  document.addEventListener("DOMContentLoaded", () => {
    const body = document.querySelector("#add-modal .modal-body");
    if (body) ORIGINAL_ADD_FORM_HTML = body.innerHTML;
  });

  // ─── Bulk Add modal ─────────────────────────────────────
  // Three input modes (range / paste / file) → parsed targets array → preview
  // (per-row checkbox + inline ID edit) → batch commit via /api/bulk-add-targets.
  let bulkParsedTargets = [];   // [{type, value, id, owner, tags, notes, _checked, _error?}]
  let bulkInputMode = "range";  // "range" | "paste" | "file"

  function openBulkModal() {
    const m = document.getElementById("bulk-modal");
    m.classList.add("open"); m.setAttribute("aria-hidden", "false");
    showBulkStage("input");
    document.getElementById("bulk-input-feedback").hidden = true;
    setTimeout(() => document.getElementById("bulk-range-input").focus(), 50);
  }
  function closeBulkModal() {
    const m = document.getElementById("bulk-modal");
    m.classList.remove("open"); m.setAttribute("aria-hidden", "true");
    bulkParsedTargets = [];
    // Reset stage visibility for next open
    showBulkStage("input");
  }
  function showBulkStage(stage) {
    document.getElementById("bulk-stage-input").hidden    = (stage !== "input");
    document.getElementById("bulk-stage-preview").hidden  = (stage !== "preview");
    document.getElementById("bulk-stage-result").hidden   = (stage !== "result");
  }

  function bindBulkUI() {
    document.getElementById("bulk-add-btn").addEventListener("click", openBulkModal);
    document.getElementById("bulk-modal-close").addEventListener("click", closeBulkModal);
    document.getElementById("bulk-cancel-btn").addEventListener("click", closeBulkModal);
    document.getElementById("bulk-preview-cancel-btn").addEventListener("click", closeBulkModal);
    document.querySelector("#bulk-modal .modal-backdrop").addEventListener("click", closeBulkModal);
    document.getElementById("bulk-back-btn").addEventListener("click", () => showBulkStage("input"));

    // Tab switching
    document.querySelectorAll(".bulk-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        bulkInputMode = tab.dataset.mode;
        document.querySelectorAll(".bulk-tab").forEach((t) => t.classList.toggle("active", t === tab));
        document.querySelectorAll(".bulk-pane").forEach((p) => p.classList.toggle("active", p.dataset.pane === bulkInputMode));
      });
    });

    // File mode → read into the paste textarea on selection
    document.getElementById("bulk-file-input").addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 100 * 1024) {
        showBulkInputFeedback("file too large — max 100 KB", "error");
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        // Stash file contents into the paste textarea + switch to paste mode visually
        document.getElementById("bulk-paste-input").value = String(reader.result || "");
        document.querySelector('.bulk-tab[data-mode="paste"]').click();
        showBulkInputFeedback(`loaded ${file.name} (${file.size} bytes) — review in Paste tab, then click Preview`, "info");
      };
      reader.readAsText(file);
    });

    document.getElementById("bulk-preview-btn").addEventListener("click", handleBulkPreview);
    document.getElementById("bulk-submit-btn").addEventListener("click", handleBulkSubmit);

    document.getElementById("bulk-attest").addEventListener("change", () => {
      const anyChecked = bulkParsedTargets.some((t) => t._checked && !t._error);
      const attested = document.getElementById("bulk-attest").checked;
      document.getElementById("bulk-submit-btn").disabled = !(anyChecked && attested);
    });

    document.getElementById("bulk-check-all").addEventListener("change", (e) => {
      const checked = e.target.checked;
      bulkParsedTargets.forEach((t) => { if (!t._error) t._checked = checked; });
      renderBulkPreview();
      updateBulkSubmitState();
    });
  }

  function showBulkInputFeedback(msg, kind) {
    const el = document.getElementById("bulk-input-feedback");
    el.hidden = false;
    // Map "error" → CSS class "err" to match the existing scale
    const cls = (kind === "error") ? "err" : (kind || "info");
    el.className = `form-feedback ${cls}`;
    el.textContent = msg;
  }

  function updateBulkSubmitState() {
    const attested = document.getElementById("bulk-attest").checked;
    const anyChecked = bulkParsedTargets.some((t) => t._checked && !t._error);
    document.getElementById("bulk-submit-btn").disabled = !(anyChecked && attested);
    const count = bulkParsedTargets.filter((t) => t._checked && !t._error).length;
    document.getElementById("bulk-preview-count").textContent =
      `${count} target${count === 1 ? "" : "s"} to add (${bulkParsedTargets.length} parsed)`;
  }

  // ─── Parsing ─────────────────────────────────────────────
  // Returns array of {type, value} (or {error}) — NOT yet enriched with metadata.
  function bulkParseRangeExpression(expr) {
    const out = [];
    const s = expr.trim();
    if (!s) return out;

    // CIDR
    if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(s)) {
      const [base, prefStr] = s.split("/");
      const pref = parseInt(prefStr, 10);
      if (pref < 16 || pref > 32) {
        return [{ error: `CIDR prefix /${pref} not allowed (use /16 to /32)`, value: s }];
      }
      const ips = expandCidrToIps(base, pref);
      if (!ips) return [{ error: `invalid CIDR: ${s}`, value: s }];
      ips.forEach((ip) => out.push({ type: "ip", value: ip }));
      return out;
    }

    // Dash range with last-octet shorthand: 24.38.70.5-14
    let m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$/);
    if (m) {
      const [, a, b, c, d1, d2] = m;
      const start = parseInt(d1, 10), end = parseInt(d2, 10);
      if (start > end || end > 255) return [{ error: `invalid range: ${s}`, value: s }];
      for (let i = start; i <= end; i++) out.push({ type: "ip", value: `${a}.${b}.${c}.${i}` });
      return out;
    }

    // Dash range with full second IP: 24.38.70.5-24.38.70.14
    m = s.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})$/);
    if (m) {
      const [, base1, d1, base2, d2] = m;
      if (base1 !== base2) return [{ error: `dash range only supports same /24 base — got ${base1} vs ${base2}`, value: s }];
      const start = parseInt(d1, 10), end = parseInt(d2, 10);
      if (start > end) return [{ error: `invalid range: ${s}`, value: s }];
      for (let i = start; i <= end; i++) out.push({ type: "ip", value: `${base1}.${i}` });
      return out;
    }

    // Comma list — first must be full IP, subsequent can be just last octet
    if (s.includes(",")) {
      const parts = s.split(/\s*,\s*/);
      const first = parts[0];
      const baseMatch = first.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})$/);
      if (!baseMatch) return [{ error: `comma list must start with a full IP, got "${first}"`, value: s }];
      const base = baseMatch[1];
      out.push({ type: "ip", value: first });
      for (let i = 1; i < parts.length; i++) {
        const p = parts[i].trim();
        if (/^\d{1,3}$/.test(p)) {
          out.push({ type: "ip", value: `${base}.${p}` });
        } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(p)) {
          out.push({ type: "ip", value: p });
        } else {
          out.push({ error: `bad entry "${p}" in comma list — expect last octet or full IP`, value: p });
        }
      }
      return out;
    }

    // Single IP
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) {
      return [{ type: "ip", value: s }];
    }

    return [{ error: `unrecognized range syntax: "${s}"`, value: s }];
  }

  function bulkParseList(text) {
    const lines = String(text || "").split(/\r?\n/);
    const out = [];
    for (let raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      // Each line can be: IP, FQDN, CIDR, or a range expression
      // CIDR / dash-range / comma list → expand via parseRangeExpression
      if (line.includes("/") || line.includes("-") || line.includes(",")) {
        const expanded = bulkParseRangeExpression(line);
        out.push(...expanded);
        continue;
      }
      // Single IP
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(line)) {
        out.push({ type: "ip", value: line });
        continue;
      }
      // FQDN (very loose check — backend validates strictly)
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(line)) {
        // Heuristic: if exactly two labels (e.g. "example.com") → apex; else fqdn
        const labels = line.split(".").length;
        out.push({ type: labels === 2 ? "apex" : "fqdn", value: line.toLowerCase() });
        continue;
      }
      out.push({ error: `unrecognized entry: "${line}"`, value: line });
    }
    return out;
  }

  // CIDR expansion helper. Returns array of dotted-quad strings, or null if invalid.
  // Excludes network and broadcast addresses for /24 and shorter prefixes (so /28 = 14 hosts).
  // For /31 and /32 we keep all addresses (RFC 3021 / single-host).
  function expandCidrToIps(base, pref) {
    const octets = base.split(".").map(Number);
    if (octets.length !== 4 || octets.some((o) => o < 0 || o > 255 || isNaN(o))) return null;
    const baseInt = (octets[0] << 24 >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
    const hostBits = 32 - pref;
    const blockSize = 1 << hostBits;
    const networkInt = baseInt - (baseInt % blockSize);
    const out = [];
    const skipNetBcast = (pref <= 30);  // skip first + last for /16-/30; keep all for /31, /32
    const start = skipNetBcast ? 1 : 0;
    const end = skipNetBcast ? blockSize - 1 : blockSize;
    for (let i = start; i < end; i++) {
      const n = networkInt + i;
      out.push([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."));
    }
    return out;
  }

  // Apply ID prefix + counter (or from-value) to parsed targets, fill in metadata
  function bulkEnrichTargets(parsed, opts) {
    const { prefix, strategy, owner, tags, notesTpl } = opts;
    const total = parsed.filter((t) => !t.error).length;
    const padWidth = String(total).length;  // 22 → "01".."22", 5 → "1".."5"
    let counter = 0;
    return parsed.map((t) => {
      if (t.error) return { ...t, _error: t.error, _checked: false };
      counter++;
      const num = String(counter).padStart(padWidth, "0");
      let id;
      if (strategy === "from-value") {
        id = t.value.replace(/[^a-z0-9]+/gi, "-").toLowerCase().replace(/^-|-$/g, "").slice(0, 64);
      } else {
        const p = (prefix || "ip-").replace(/[^a-z0-9-]/gi, "-").toLowerCase();
        id = `${p}${num}`.slice(0, 64);
      }
      const notes = (notesTpl || "").replace(/\$\{IP\}|\$\{VALUE\}/g, t.value);
      return {
        type:    t.type,
        value:   t.value,
        id,
        owner:   (owner || "command_digital").trim(),
        tags:    (tags || "").split(",").map((s) => s.trim()).filter(Boolean),
        notes,
        _checked: true,
      };
    });
  }

  function handleBulkPreview() {
    const fb = document.getElementById("bulk-input-feedback");
    fb.hidden = true;

    let parsed = [];
    if (bulkInputMode === "range") {
      const expr = document.getElementById("bulk-range-input").value;
      parsed = bulkParseRangeExpression(expr);
    } else {
      // Both "paste" and "file" mode read from the textarea
      const text = document.getElementById("bulk-paste-input").value;
      parsed = bulkParseList(text);
    }

    if (!parsed.length) {
      showBulkInputFeedback("nothing parsed — enter a range, list, or upload a file", "error");
      return;
    }

    const opts = {
      prefix:   document.getElementById("bulk-id-prefix").value || "ip-",
      strategy: document.getElementById("bulk-id-strategy").value || "counter",
      owner:    document.getElementById("bulk-owner").value || "command_digital",
      tags:     document.getElementById("bulk-tags").value || "",
      notesTpl: document.getElementById("bulk-notes").value || "",
    };

    bulkParsedTargets = bulkEnrichTargets(parsed, opts);

    // Sanity cap mirrors backend
    if (bulkParsedTargets.length > 100) {
      showBulkInputFeedback(`parsed ${bulkParsedTargets.length} entries — max 100 per batch. Trim your input and try again.`, "error");
      return;
    }

    // Reset attestation + render preview
    document.getElementById("bulk-attest").checked = false;
    document.getElementById("bulk-check-all").checked = true;
    document.getElementById("bulk-preview-feedback").hidden = true;
    showBulkStage("preview");
    renderBulkPreview();
    updateBulkSubmitState();
  }

  function renderBulkPreview() {
    const tbody = document.getElementById("bulk-preview-tbody");
    const html = bulkParsedTargets.map((t, i) => {
      if (t._error) {
        return `
          <tr class="bulk-row-error">
            <td class="col-check">—</td>
            <td class="col-type">—</td>
            <td class="col-value td-mono">${escapeHtml(t.value || "")}</td>
            <td class="col-id">—</td>
            <td class="col-status"><span class="bulk-status-error">${escapeHtml(t._error)}</span></td>
          </tr>
        `;
      }
      return `
        <tr data-idx="${i}">
          <td class="col-check"><input type="checkbox" class="bulk-row-check" data-idx="${i}" ${t._checked ? "checked" : ""} /></td>
          <td class="col-type"><span class="bulk-type-pill">${escapeHtml(t.type.toUpperCase())}</span></td>
          <td class="col-value td-mono">${escapeHtml(t.value)}</td>
          <td class="col-id">
            <input type="text" class="bulk-id-input" data-idx="${i}" value="${escapeAttr(t.id)}" pattern="^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$" />
          </td>
          <td class="col-status"><span class="bulk-status-ready">ready</span></td>
        </tr>
      `;
    }).join("");
    tbody.innerHTML = html;

    // Wire up per-row controls
    tbody.querySelectorAll(".bulk-row-check").forEach((el) => {
      el.addEventListener("change", (e) => {
        const idx = Number(e.target.dataset.idx);
        bulkParsedTargets[idx]._checked = e.target.checked;
        updateBulkSubmitState();
      });
    });
    tbody.querySelectorAll(".bulk-id-input").forEach((el) => {
      el.addEventListener("input", (e) => {
        const idx = Number(e.target.dataset.idx);
        bulkParsedTargets[idx].id = e.target.value.trim();
        // visual hint: invalid pattern → red border
        e.target.classList.toggle("bulk-id-invalid", !/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(bulkParsedTargets[idx].id));
      });
    });
  }

  async function handleBulkSubmit() {
    const submitBtn = document.getElementById("bulk-submit-btn");
    const fb = document.getElementById("bulk-preview-feedback");
    fb.hidden = false; fb.className = "form-feedback info"; fb.textContent = "Submitting batch…";
    submitBtn.disabled = true;

    // Pre-flight: any checked row with invalid ID? Bail.
    const selected = bulkParsedTargets.filter((t) => t._checked && !t._error);
    const badIds = selected.filter((t) => !/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(t.id));
    if (badIds.length) {
      fb.className = "form-feedback err";
      fb.textContent = `${badIds.length} ID(s) invalid — fix highlighted rows. Pattern: lowercase letters/digits/hyphens, 3-64 chars.`;
      submitBtn.disabled = false;
      return;
    }

    const payload = {
      attest: true,
      targets: selected.map((t) => ({
        id:    t.id,
        type:  t.type,
        value: t.value,
        owner: t.owner,
        tags:  t.tags,
        notes: t.notes,
      })),
    };

    try {
      const r = await fetch("/api/bulk-add-targets", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok || !data.ok) {
        fb.className = "form-feedback err";
        const detail = Array.isArray(data.details) ? `\n  - ${data.details.join("\n  - ")}` : "";
        fb.textContent = `Failed: ${data.error || `HTTP ${r.status}`}${detail}`;
        submitBtn.disabled = false;
        return;
      }
      // Success → switch to result stage
      renderBulkResult(data, payload);
      // Kick off the global watcher so the top-bar pill picks up the run
    } catch (e) {
      fb.className = "form-feedback err";
      fb.textContent = `Network error: ${e.message}`;
      submitBtn.disabled = false;
    }
  }

  function renderBulkResult(data, payload) {
    showBulkStage("result");
    const sha = data.commit?.sha?.slice(0, 7) || "";
    const commitUrl = data.commit?.url || "";
    const actionsUrl = "https://github.com/bklynhowster/commandsentry-asm/actions/workflows/asm-discover.yml";
    const idChips = (data.target_ids || []).map((id) => `<span class="bulk-id-chip">${escapeHtml(id)}</span>`).join("");
    const skippedChips = (data.skipped || []).map((s) => `<span class="bulk-id-chip bulk-id-chip-skip">${escapeHtml(s.id)} <em>(${escapeHtml(s.reason)})</em></span>`).join("");
    document.getElementById("bulk-stage-result").innerHTML = `
      <div class="add-success">
        <div class="add-success-head">
          <div class="add-success-checkmark">✓</div>
          <div>
            <div class="add-success-title">Batch committed — ${data.added_count} target${data.added_count === 1 ? "" : "s"} queued</div>
            <div class="add-success-subtitle">Single diff-aware run will scan all newly-added IDs.</div>
          </div>
        </div>

        <div class="bulk-result-section">
          <div class="bulk-result-label">Added (${data.added_count})</div>
          <div class="bulk-result-chips">${idChips || "<span class='muted'>none</span>"}</div>
        </div>

        ${(data.skipped || []).length ? `
          <div class="bulk-result-section">
            <div class="bulk-result-label">Skipped (${data.skipped.length})</div>
            <div class="bulk-result-chips">${skippedChips}</div>
          </div>
        ` : ""}

        <div class="add-success-footnote">
          Watch the top-bar pill for live status. Each target's asset card will appear in the inventory once its scan completes (~12 min per target, serial).
        </div>

        <div class="add-success-actions">
          ${commitUrl ? `<a href="${escapeAttr(commitUrl)}" target="_blank" rel="noopener" class="btn-link">View commit on GitHub →</a>` : ""}
          <a href="${escapeAttr(actionsUrl)}" target="_blank" rel="noopener" class="btn-link">Watch workflow run →</a>
          <div class="add-success-actions-buttons">
            <button type="button" id="bulk-add-more-btn" class="btn-ghost">Add another batch</button>
            <button type="button" id="bulk-done-btn" class="btn-accent">Done</button>
          </div>
        </div>
      </div>
    `;
    document.getElementById("bulk-done-btn").addEventListener("click", closeBulkModal);
    document.getElementById("bulk-add-more-btn").addEventListener("click", () => {
      bulkParsedTargets = [];
      document.getElementById("bulk-range-input").value = "";
      document.getElementById("bulk-paste-input").value = "";
      document.getElementById("bulk-file-input").value = "";
      showBulkStage("input");
    });
  }

  // Bind bulk UI on DOM ready
  document.addEventListener("DOMContentLoaded", bindBulkUI);
})();
