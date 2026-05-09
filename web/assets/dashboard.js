/* COMMANDsentry — dashboard (v2 ASM schema)
   Vanilla JS, no framework. Reads ./data/_manifest.json + per-asset JSON.
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
  };

  // ─── boot ────────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", async () => {
    bindUI();
    try { await loadAll(); }
    catch (e) { return showLoadError(e); }
    setView(state.activeView);
    render();
  });

  // ─── loaders ─────────────────────────────────────────────
  async function loadAll() {
    let manifest;
    try {
      const r = await fetch(MANIFEST, { cache: "no-store" });
      if (!r.ok) throw new Error(`manifest ${r.status}`);
      manifest = await r.json();
    } catch (e) {
      throw new Error(`Couldn't load ${MANIFEST}: ${e.message}. Run web/sync-data.sh first.`);
    }
    const ids = manifest.assets || [];
    if (!ids.length) throw new Error("Manifest has no assets. Run a scan first, then web/sync-data.sh.");

    const results = await Promise.all(
      ids.map(async (id) => {
        try {
          const r = await fetch(`${DATA_DIR}/${id}.json`, { cache: "no-store" });
          if (!r.ok) return null;
          return await r.json();
        } catch { return null; }
      })
    );
    state.assets = results.filter(Boolean);
  }

  function showLoadError(e) {
    const el = document.getElementById("view-loading");
    if (!el) return;
    el.innerHTML = `<div class="empty"><strong>${escapeHtml(e.message)}</strong></div>`;
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
      state.filterTag = e.target.value;
      renderInventory();
    });
    document.getElementById("filter-owner").addEventListener("change", (e) => {
      state.filterOwner = e.target.value;
      renderInventory();
    });
    document.getElementById("drawer-close").addEventListener("click", closeDrawer);
    document.querySelector(".drawer-backdrop").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { closeDrawer(); closeAddModal(); }
    });

    // Add Target modal
    document.getElementById("add-target-btn").addEventListener("click", openAddModal);
    document.getElementById("add-modal-close").addEventListener("click", closeAddModal);
    document.getElementById("add-cancel-btn").addEventListener("click", closeAddModal);
    document.querySelector("#add-modal .modal-backdrop").addEventListener("click", closeAddModal);
    document.getElementById("add-target-form").addEventListener("submit", handleAddSubmit);
    document.querySelectorAll("input[name=\"type\"]").forEach((r) => {
      r.addEventListener("change", updateTypeHelp);
    });
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
    const newest = state.assets
      .map((a) => a.scan?.completed_at)
      .filter(Boolean)
      .sort()
      .pop();
    el.textContent = `${state.assets.length} asset${state.assets.length === 1 ? "" : "s"} · last scan ${formatRelTime(newest)}`;
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

  // ─── inventory cards ─────────────────────────────────────
  function renderInventory() {
    const grid = document.getElementById("inventory-grid");
    const filtered = state.assets.filter(matchesFilter);
    if (!filtered.length) {
      grid.innerHTML = `<div class="empty">${state.assets.length ? "No matches." : "No assets yet."}</div>`;
      return;
    }
    grid.innerHTML = filtered.map(renderAssetCard).join("");
    grid.querySelectorAll(".asset-card").forEach((card) => {
      card.addEventListener("click", () => openDrawer(card.dataset.id));
    });
  }

  function matchesFilter(a) {
    if (state.filterTag && !(a.asset?.tags || []).includes(state.filterTag)) return false;
    if (state.filterOwner && a.asset?.owner !== state.filterOwner) return false;
    if (state.filterText) {
      const hay = [
        a.asset?.value, a.asset?.id, a.asset?.owner,
        ...(a.asset?.tags || []),
        ...((a.fingerprint?.tech || []).map((t) => t.name)),
        ...((a.hosts || []).map((h) => h.asn_org)),
      ].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(state.filterText)) return false;
    }
    return true;
  }

  function renderAssetCard(a) {
    const hostCount = (a.hosts || []).length;
    const svcCount = (a.services || []).length;
    const subAlive = (a.subdomains || []).filter((s) => s.alive).length;
    const live = a.reachability?.live;
    const wafVendor = a.waf?.detected ? a.waf.vendor : null;

    // Hosting attribution — most common ASN org becomes the "hosted by" label
    const hostingOrg = topHostingOrg(a.hosts || []);
    const hostingClass = hostingClassFor(hostingOrg);
    const platformLabel = a.fingerprint?.platform_label;

    return `
      <div class="asset-card" data-id="${escapeAttr(a.asset?.id || "")}">
        <div class="asset-card-head">
          <div class="asset-card-title-block">
            <div class="status-dot ${live ? "live" : "down"}" aria-label="${live ? "live" : "offline"}"></div>
            <div class="asset-card-title">${escapeHtml(a.asset?.value || a.asset?.id || "?")}</div>
          </div>
          <span class="asset-card-type">${escapeHtml((a.asset?.type || "").toUpperCase())}</span>
        </div>

        <div class="asset-stats">
          <div class="stat"><span class="stat-num" data-count="${hostCount}">0</span><span class="stat-label">host${hostCount === 1 ? "" : "s"}</span></div>
          <div class="stat"><span class="stat-num" data-count="${svcCount}">0</span><span class="stat-label">service${svcCount === 1 ? "" : "s"}</span></div>
          <div class="stat"><span class="stat-num" data-count="${subAlive}">0</span><span class="stat-label">sub${subAlive === 1 ? "" : "s"}</span></div>
        </div>

        <div class="asset-card-row">
          ${hostingOrg ? `<span class="hosting-pill ${hostingClass}">${escapeHtml(hostingOrg)}</span>` : ""}
          ${wafVendor ? `<span class="waf-pill"><span class="waf-pill-icon">⛨</span>${escapeHtml(wafVendor)}</span>` : ""}
          ${platformLabel ? `<span class="platform-pill">${escapeHtml(platformLabel)}</span>` : ""}
        </div>

        ${(a.asset?.tags || []).length ? `<div class="tag-row">${a.asset.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
      </div>
    `;
  }

  function topHostingOrg(hosts) {
    const counts = new Map();
    for (const h of hosts) {
      const org = (h.asn_org || "").trim();
      if (!org) continue;
      counts.set(org, (counts.get(org) || 0) + 1);
    }
    if (!counts.size) return null;
    return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
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
    return "h-other";
  }

  // animated counter on cards (called after render)
  function animateCounters(scope) {
    scope.querySelectorAll("[data-count]").forEach((el) => {
      const target = parseInt(el.dataset.count, 10);
      if (!Number.isFinite(target) || target === 0) { el.textContent = "0"; return; }
      const duration = 600;
      const start = performance.now();
      const step = (now) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
        el.textContent = Math.round(target * eased);
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  }

  // ─── what changed feed ──────────────────────────────────
  function renderChanged() {
    const feed = document.getElementById("changed-feed");
    const events = [];
    state.assets.forEach((a) => {
      const aname = a.asset?.value || a.asset?.id;
      const d = a.deltas || {};
      (d.added?.subdomains   || []).forEach((s) => events.push(["added",   "+", `New subdomain discovered: ${s}`, aname]));
      (d.added?.hosts        || []).forEach((h) => events.push(["added",   "+", `New host IP: ${h.ip}`, aname]));
      (d.added?.services     || []).forEach((s) => events.push(["added",   "+", `New service: port ${s.port}/${s.protocol}`, aname]));
      (d.removed?.subdomains || []).forEach((s) => events.push(["removed", "−", `Subdomain went away: ${s}`, aname]));
      (d.removed?.hosts      || []).forEach((h) => events.push(["removed", "−", `Host IP removed: ${h.ip}`, aname]));
      (d.removed?.services   || []).forEach((s) => events.push(["removed", "−", `Service closed: port ${s.port}/${s.protocol}`, aname]));
      (d.changed?.fingerprint || []).forEach((t) => events.push(["changed","Δ", `${t.name}: ${t.from || "?"} → ${t.to || "?"}`, aname]));
      (d.changed?.cert        || []).forEach((c) => events.push(["changed","Δ", `Cert chain changed: ${(c.from || []).join(", ")} → ${(c.to || []).join(", ")}`, aname]));
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

  // ─── drawer ──────────────────────────────────────────────
  function openDrawer(id) {
    const a = state.assets.find((x) => x.asset?.id === id);
    if (!a) return;

    document.getElementById("drawer-title").textContent = a.asset?.value || a.asset?.id;
    document.getElementById("drawer-body").innerHTML = renderDrawerBody(a);

    document.getElementById("drawer").classList.add("open");
    document.getElementById("drawer").setAttribute("aria-hidden", "false");
    animateCounters(document.getElementById("drawer-body"));
  }

  function closeDrawer() {
    const d = document.getElementById("drawer");
    d.classList.remove("open");
    d.setAttribute("aria-hidden", "true");
  }

  function renderDrawerBody(a) {
    const live      = a.reachability?.live;
    const status    = a.reachability?.http_status;
    const wafVendor = a.waf?.detected ? a.waf.vendor : null;
    const hostingOrg = topHostingOrg(a.hosts || []);
    const certNearest = nearestCertExpiry(a.services || []);
    const hostCount = (a.hosts || []).length;
    const svcCount  = (a.services || []).length;
    const subCount  = (a.subdomains || []).filter((s) => s.alive).length;

    return `
      ${renderVerdictStrip(a, { live, status, wafVendor, hostingOrg, certNearest, hostCount, svcCount, subCount })}
      ${renderHostsSection(a)}
      ${renderServicesSection(a)}
      ${renderSubdomainsSection(a)}
      ${renderDnsSection(a)}
      ${renderRegistrationSection(a)}
      ${renderFingerprintSection(a)}
      ${renderProvenanceSection(a)}
    `;
  }

  function nearestCertExpiry(services) {
    let nearest = null;
    for (const s of services) {
      const days = s.cert?.days_to_expiry;
      if (typeof days === "number" && (nearest === null || days < nearest)) nearest = days;
    }
    return nearest;
  }

  // ─── verdict strip (top of drawer) ───────────────────────
  function renderVerdictStrip(a, ctx) {
    const { live, status, wafVendor, hostingOrg, certNearest, hostCount, svcCount, subCount } = ctx;
    const certBadge = certNearest === null ? null
      : certNearest < 7 ? { label: `Cert expires in ${certNearest}d`, cls: "v-bad" }
      : certNearest < 30 ? { label: `Cert expires in ${certNearest}d`, cls: "v-warn" }
      : { label: `Cert valid ${certNearest}d`, cls: "v-good" };

    return `
      <div class="verdict-strip">
        <div class="verdict-row">
          <div class="verdict-pill ${live ? "v-good" : "v-bad"}">
            <span class="status-dot ${live ? "live" : "down"}"></span>
            ${live ? `Live · HTTP ${status || "?"}` : "Offline"}
          </div>
          ${hostingOrg ? `<div class="verdict-pill v-info hosting-pill ${hostingClassFor(hostingOrg)}">${escapeHtml(hostingOrg)}</div>` : ""}
          ${wafVendor ? `<div class="verdict-pill v-info waf-pill"><span class="waf-pill-icon">⛨</span>${escapeHtml(wafVendor)}</div>` : ""}
          ${certBadge ? `<div class="verdict-pill ${certBadge.cls}"><span class="v-icon">🔒</span>${escapeHtml(certBadge.label)}</div>` : ""}
        </div>
        <div class="verdict-stats">
          <div class="stat-big"><div class="stat-num" data-count="${hostCount}">0</div><div class="stat-label">${hostCount === 1 ? "host" : "hosts"}</div></div>
          <div class="stat-big"><div class="stat-num" data-count="${svcCount}">0</div><div class="stat-label">${svcCount === 1 ? "service" : "services"}</div></div>
          <div class="stat-big"><div class="stat-num" data-count="${subCount}">0</div><div class="stat-label">${subCount === 1 ? "subdomain" : "subdomains"}</div></div>
        </div>
      </div>
    `;
  }

  // ─── hosts section ───────────────────────────────────────
  function renderHostsSection(a) {
    const hosts = a.hosts || [];
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

  // ─── services section ────────────────────────────────────
  function renderServicesSection(a) {
    const services = a.services || [];
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

  // ─── subdomains section ──────────────────────────────────
  function renderSubdomainsSection(a) {
    const subs = a.subdomains || [];
    if (!subs.length) return "";
    const rows = subs.map((s) => `
      <tr>
        <td class="td-mono">
          <span class="status-dot ${s.alive ? "live" : "down"}"></span>
          ${escapeHtml(s.name)}
        </td>
        <td class="muted">${s.alive ? "alive" : "down"}</td>
        <td class="td-mono muted">${formatRelTime(s.last_seen)}</td>
      </tr>`).join("");
    return section(`Subdomains (${subs.filter((s) => s.alive).length} alive of ${subs.length})`, `
      <table class="data-table">
        <thead><tr><th>Name</th><th>Status</th><th>Last seen</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `);
  }

  // ─── dns section ─────────────────────────────────────────
  function renderDnsSection(a) {
    const d = a.dns || {};
    if (!d.a?.length && !d.ns?.length) return "";
    const rows = [
      ["A",     (d.a || []).join(", ")],
      ["AAAA",  (d.aaaa || []).join(", ")],
      ["CNAME", d.cname],
      ["MX",    (d.mx || []).map((m) => `${m.priority} ${m.host}`).join(", ")],
      ["NS",    (d.ns || []).join(", ")],
      ["SPF",   d.spf],
      ["DNSSEC",d.dnssec ? "enabled" : "disabled"],
    ].filter(([, v]) => v && v.length);
    return section("DNS", kvTable(rows));
  }

  // ─── registration ────────────────────────────────────────
  function renderRegistrationSection(a) {
    const r = a.registration || {};
    if (!Object.keys(r).length) return "";
    return section("Registration (whois)", kvTable([
      ["Registrar", r.registrar],
      ["URL",       r.registrar_url],
      ["Created",   r.created],
      ["Updated",   r.updated],
      ["Expires",   r.expires],
      ["Status",    r.status],
    ]));
  }

  // ─── tech fingerprint ────────────────────────────────────
  function renderFingerprintSection(a) {
    const fp = a.fingerprint || {};
    if (!fp.tech?.length && !fp.server) return "";
    const grouped = groupTech(fp.tech || []);
    const groups = Object.entries(grouped);
    return section("Tech fingerprint",  `
      ${fp.platform_label ? `<div class="platform-banner">${escapeHtml(fp.platform_label)}</div>` : ""}
      <div class="tech-groups">
        ${groups.map(([cat, items]) => `
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

  // ─── provenance ──────────────────────────────────────────
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

  // ─── helpers ─────────────────────────────────────────────
  function section(title, body) {
    return `<div class="drawer-section"><h4>${escapeHtml(title)}</h4>${body}</div>`;
  }

  function kvTable(rows) {
    return `<table class="kv-table">${rows
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`)
      .join("")}</table>`;
  }

  // ─── Add Target modal (unchanged from v1) ────────────────
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
    const t = document.querySelector("input[name=\"type\"]:checked")?.value || "fqdn";
    const help = document.getElementById("t-type-help");
    const valueInput = document.getElementById("t-value");
    const placeholders = {
      fqdn: { help: "Single hostname — scans just this host (e.g. <code>www.example.com</code>)", ph: "www.example.com" },
      apex: { help: "Apex domain — enumerates subdomains via passive sources", ph: "example.com" },
      ip:   { help: "Single IPv4 — port + service discovery, no DNS context", ph: "198.51.100.42" },
      cidr: { help: "CIDR range — naabu sweeps the range for live hosts", ph: "198.51.100.0/29" },
    };
    help.innerHTML = placeholders[t].help;
    valueInput.placeholder = placeholders[t].ph;
    const idInput = document.getElementById("t-id");
    idInput.placeholder = (t === "ip") ? "host-198-51-100-42" : (t === "cidr") ? "range-198-51-100-0-29" : "example-www";
  }
  function autofillId() {
    const idInput = document.getElementById("t-id");
    if (idInput.dataset.touched === "true") return;
    const value = document.getElementById("t-value").value.trim().toLowerCase();
    const type  = document.querySelector("input[name=\"type\"]:checked")?.value || "fqdn";
    if (!value) { idInput.value = ""; return; }
    let id = (type === "fqdn" || type === "apex")
      ? value.replace(/^www\./, "").replace(/[^a-z0-9-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "")
      : value.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    idInput.value = id.slice(0, 64);
  }
  async function handleAddSubmit(e) {
    e.preventDefault();
    const submitBtn = document.getElementById("add-submit-btn");
    const feedback  = document.getElementById("add-form-feedback");
    feedback.hidden = false;
    feedback.className = "form-feedback info";
    feedback.textContent = "Submitting…";
    submitBtn.disabled = true;

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
        feedback.className = "form-feedback ok";
        feedback.innerHTML = `Target <code>${escapeHtml(payload.id)}</code> added. Commit: <code>${escapeHtml((data.commit?.sha || "").slice(0, 7))}</code>. Scan will run within ~10 min.`;
        e.target.reset();
        document.getElementById("t-id").dataset.touched = "false";
        updateTypeHelp();
        submitBtn.disabled = false;
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

  // ─── primitives ──────────────────────────────────────────
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
    const d = Math.floor(hr / 24);
    return `${d}d ago`;
  }
  function escapeHtml(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function escapeAttr(s) { return escapeHtml(s); }
})();
