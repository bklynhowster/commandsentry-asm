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
  });

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
          ${topOrg ? `<span class="hosting-pill ${hostingClassFor(topOrg)}">${escapeHtml(topOrg)}</span>` : ""}
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
          ${sm.top_hosting_org ? `<div class="verdict-pill v-info hosting-pill ${hostingClassFor(sm.top_hosting_org)}">${escapeHtml(sm.top_hosting_org)}</div>` : ""}
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
      const topOrg = s.hosts?.[0]?.asn_org;
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
          <td>${topOrg ? `<span class="hosting-pill ${hostingClassFor(topOrg)}">${escapeHtml(topOrg)}</span>` : "<span class='muted'>—</span>"}</td>
          <td>${waf ? `<span class="waf-pill"><span class="waf-pill-icon">⛨</span>${escapeHtml(waf)}</span>` : "<span class='muted'>—</span>"}</td>
          <td>${typeof certDays === "number" ? renderCertDaysBadge(certDays) : "<span class='muted'>—</span>"}</td>
          <td class="td-arrow">→</td>
        </tr>`;
    }).join("");
    return section(`Subdomains (${subs.length})`, `
      <table class="data-table sub-table">
        <thead><tr><th>Name</th><th>Hosts</th><th>Svcs</th><th>Hosting</th><th>WAF</th><th>Cert</th><th></th></tr></thead>
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
          ${topOrg ? `<div class="verdict-pill v-info hosting-pill ${hostingClassFor(topOrg)}">${escapeHtml(topOrg)}</div>` : ""}
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

  // Replace the form body with a clear success state — what just happened,
  // what's happening now, what to expect, with action buttons.
  function showAddSuccess(payload, data) {
    const body = document.querySelector("#add-modal .modal-body");
    const sha = (data.commit?.sha || "").slice(0, 7);
    const commitUrl = data.commit?.url || "";
    const actionsUrl = "https://github.com/bklynhowster/commandsentry-asm/actions/workflows/asm-discover.yml";
    const isApex = payload.type === "apex";

    const expectedTime = isApex
      ? "10–30 minutes"
      : payload.type === "cidr" ? "15–45 minutes" : "8–12 minutes";

    const timeline = isApex ? [
      { state: "done",    label: "Target committed to repo",                      detail: sha ? `commit ${sha}` : "" },
      { state: "running", label: "Scan workflow triggered",                       detail: "GitHub Actions queueing" },
      { state: "pending", label: "Subdomain enumeration (subfinder)",             detail: "passive sources — crt.sh, BufferOver, etc." },
      { state: "pending", label: "Liveness check (httpx) on each candidate",      detail: "filters to subs that respond" },
      { state: "pending", label: "Per-subdomain deep scan",                       detail: "DNS, ports, services, cert, fingerprint, WAF — ~5–7 min each" },
      { state: "pending", label: "Asset JSON committed",                          detail: "bot pushes results back to main" },
      { state: "pending", label: "Dashboard auto-deploys",                        detail: "Netlify rebuild ~1–2 min" },
      { state: "pending", label: "Email alert sent",                              detail: "first-scan notification" },
    ] : [
      { state: "done",    label: "Target committed to repo",                      detail: sha ? `commit ${sha}` : "" },
      { state: "running", label: "Scan workflow triggered",                       detail: "GitHub Actions queueing" },
      { state: "pending", label: "DNS resolution + WHOIS",                        detail: "" },
      { state: "pending", label: "Port discovery + service fingerprinting",       detail: "" },
      { state: "pending", label: "HTTP probe + cert + WAF detection",             detail: "" },
      { state: "pending", label: "Asset JSON committed",                          detail: "" },
      { state: "pending", label: "Dashboard auto-deploys + email alert",          detail: "" },
    ];

    body.innerHTML = `
      <div class="add-success">
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

        <div class="add-success-timing">
          <div class="add-success-timing-label">Expected total time</div>
          <div class="add-success-timing-value">${escapeHtml(expectedTime)}</div>
          <div class="add-success-timing-note">
            ${isApex
              ? "Apex scans depend on how many live subdomains subfinder uncovers — each one gets its own deep scan."
              : "Single-target scan, runs the full discovery flow once."}
          </div>
        </div>

        <div class="add-success-timeline">
          <div class="add-success-timeline-label">What happens next</div>
          ${timeline.map((step) => `
            <div class="step-row step-${step.state}">
              <div class="step-icon">${step.state === "done" ? "✓" : step.state === "running" ? "●" : "○"}</div>
              <div class="step-body">
                <div class="step-label">${escapeHtml(step.label)}</div>
                ${step.detail ? `<div class="step-detail">${escapeHtml(step.detail)}</div>` : ""}
              </div>
            </div>
          `).join("")}
        </div>

        <div class="add-success-footnote">
          You don't need to keep this open. The dashboard refreshes itself when the scan finishes.
          You'll also get an email when it's done.
        </div>

        <div class="add-success-actions">
          ${commitUrl ? `<a href="${escapeAttr(commitUrl)}" target="_blank" rel="noopener" class="btn-link">View commit on GitHub →</a>` : ""}
          <a href="${escapeAttr(actionsUrl)}" target="_blank" rel="noopener" class="btn-link">Watch workflow run →</a>
          <div class="add-success-actions-buttons">
            <button type="button" id="add-another-btn" class="btn-ghost">Add another target</button>
            <button type="button" id="add-done-btn" class="btn-accent">Done</button>
          </div>
        </div>
      </div>
    `;

    document.getElementById("add-done-btn").addEventListener("click", closeAddModal);
    document.getElementById("add-another-btn").addEventListener("click", () => {
      // Restore the form for another add
      restoreAddForm();
    });
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
})();
