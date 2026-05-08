/* COMMANDsentry — dashboard
   Vanilla JS, no framework. Reads ./data/_manifest.json + per-asset JSON files.
   ──────────────────────────────────────────────────────────────────────────── */

(() => {
  "use strict";

  const DATA_DIR = "./data";
  const MANIFEST = `${DATA_DIR}/_manifest.json`;

  /** @type {Array<object>} */
  const state = {
    assets: [],
    filterText: "",
    filterTag: "",
    filterOwner: "",
    activeView: "inventory",
  };

  // ─── boot ──────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", async () => {
    bindUI();
    try {
      await loadAll();
    } catch (e) {
      showLoadError(e);
      return;
    }
    setView(state.activeView);
    render();
  });

  // ─── loaders ───────────────────────────────────────────
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
          const j = await r.json();
          return j;
        } catch {
          return null;
        }
      })
    );
    state.assets = results.filter(Boolean);
  }

  function showLoadError(e) {
    const el = document.getElementById("view-loading");
    if (!el) return;
    el.innerHTML = `<div class="empty"><strong>${escapeHtml(e.message)}</strong><br><br>
      <span class="muted">From the repo root, run:</span><br>
      <code>./web/sync-data.sh</code><br>
      <span class="muted">then refresh.</span></div>`;
  }

  // ─── ui binding ────────────────────────────────────────
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

    // Auto-fill ID + update help text from value/type
    document.querySelectorAll("input[name=\"type\"]").forEach((r) => {
      r.addEventListener("change", updateTypeHelp);
    });
    document.getElementById("t-value").addEventListener("input", autofillId);
  }

  function setView(name) {
    state.activeView = name;
    document.querySelectorAll(".tab").forEach((t) => {
      t.classList.toggle("active", t.dataset.view === name);
    });
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    const target = document.getElementById(`view-${name}`);
    if (target) target.classList.add("active");
    render();
  }

  // ─── rendering ─────────────────────────────────────────
  function render() {
    renderTopbar();
    renderInventory();
    renderChanged();
    renderWatch();
    populateFilters();
  }

  function renderTopbar() {
    const el = document.getElementById("last-scan-summary");
    if (!state.assets.length) { el.textContent = "no data"; return; }
    const newest = state.assets
      .map((a) => a.scan && a.scan.completed_at)
      .filter(Boolean)
      .sort()
      .pop();
    el.textContent = `${state.assets.length} asset${state.assets.length === 1 ? "" : "s"} · last scan ${formatRelTime(newest)}`;
  }

  function populateFilters() {
    const tagSel = document.getElementById("filter-tag");
    const ownerSel = document.getElementById("filter-owner");
    const tags = new Set();
    const owners = new Set();
    state.assets.forEach((a) => {
      (a.asset?.tags || []).forEach((t) => tags.add(t));
      if (a.asset?.owner) owners.add(a.asset.owner);
    });
    fillSelect(tagSel, Array.from(tags).sort(), "All tags");
    fillSelect(ownerSel, Array.from(owners).sort(), "All owners");
  }

  function fillSelect(sel, items, defaultLabel) {
    const cur = sel.value;
    sel.innerHTML = `<option value="">${defaultLabel}</option>` +
      items.map((v) => `<option value="${escapeAttr(v)}">${escapeHtml(v)}</option>`).join("");
    if (items.includes(cur)) sel.value = cur;
  }

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
        ...((a.inventory?.http?.technologies || []).map((t) => t.name)),
      ].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(state.filterText)) return false;
    }
    return true;
  }

  function renderAssetCard(a) {
    const inv = a.inventory || {};
    const sumByPrio = countExposures(a);
    const techList = (inv.http?.technologies || []).slice(0, 4).map((t) =>
      t.version ? `${t.name} ${t.version}` : t.name
    );
    const ipCount = (inv.identity?.ip_addresses || []).length;
    const portCount = (inv.ports || []).length;
    const subAlive = (inv.subdomains || []).filter((s) => s.alive).length;
    const waf = inv.waf?.detected ? `WAF: ${inv.waf.vendor || "yes"}` : "no WAF";

    const expoPills = [
      sumByPrio.watch ? `<span class="exposure-pill watch">${sumByPrio.watch} watch</span>` : "",
      sumByPrio.notice ? `<span class="exposure-pill notice">${sumByPrio.notice} notice</span>` : "",
      !sumByPrio.watch && !sumByPrio.notice ? `<span class="exposure-pill zero">clean</span>` : "",
    ].filter(Boolean).join("");

    return `
      <div class="asset-card" data-id="${escapeAttr(a.asset?.id || "")}">
        <div class="asset-card-head">
          <div class="asset-card-title">${escapeHtml(a.asset?.value || a.asset?.id || "?")}</div>
          <span class="asset-card-type">${escapeHtml((a.asset?.type || "").toUpperCase())}</span>
        </div>
        <div class="asset-card-row">
          <span class="kv"><span class="kv-key">ip</span>${ipCount}</span>
          <span class="kv"><span class="kv-key">ports</span>${portCount}</span>
          <span class="kv"><span class="kv-key">subs</span>${subAlive}</span>
          <span class="kv"><span class="kv-key">waf</span>${escapeHtml(waf)}</span>
        </div>
        ${techList.length ? `<div class="asset-card-row">${techList.map((t) => `<span class="kv">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
        ${(a.asset?.tags || []).length ? `<div class="tag-row">${(a.asset.tags || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
        <div class="asset-card-row" style="margin-top: auto;">${expoPills}</div>
      </div>
    `;
  }

  function countExposures(a) {
    const out = { notice: 0, watch: 0 };
    (a.exposures || []).forEach((e) => {
      if (e.severity === "watch") out.watch += 1;
      else if (e.severity === "notice") out.notice += 1;
    });
    return out;
  }

  function renderChanged() {
    const feed = document.getElementById("changed-feed");
    const events = [];
    state.assets.forEach((a) => {
      const aname = a.asset?.value || a.asset?.id;
      const d = a.deltas || {};
      (d.added?.subdomains || []).forEach((s) => events.push({ type: "added", icon: "+", text: `New subdomain: ${s}`, asset: aname }));
      (d.added?.ports || []).forEach((p) => events.push({ type: "added", icon: "+", text: `New open port: ${p.port}/${p.protocol}`, asset: aname }));
      (d.added?.exposures || []).forEach((id) => {
        const exp = (a.exposures || []).find((e) => e.id === id);
        events.push({ type: "added", icon: "+", text: `New exposure: ${exp?.title || id}`, asset: aname });
      });
      (d.removed?.subdomains || []).forEach((s) => events.push({ type: "removed", icon: "−", text: `Subdomain gone: ${s}`, asset: aname }));
      (d.removed?.ports || []).forEach((p) => events.push({ type: "removed", icon: "−", text: `Port closed: ${p.port}/${p.protocol}`, asset: aname }));
      (d.removed?.exposures || []).forEach((id) => events.push({ type: "removed", icon: "−", text: `Exposure resolved: ${id}`, asset: aname }));
      (d.changed?.tech || []).forEach((t) => events.push({ type: "changed", icon: "Δ", text: `${t.name}: ${t.from || "?"} → ${t.to || "?"}`, asset: aname }));
    });

    if (!events.length) {
      feed.innerHTML = `<div class="empty">No changes detected since the previous scan.<br><span class="muted">Either nothing changed, or this is the first scan for these assets.</span></div>`;
      return;
    }

    feed.innerHTML = events.map((e) => `
      <div class="feed-row ${e.type}">
        <span class="feed-icon">${escapeHtml(e.icon)}</span>
        <div style="flex: 1;">
          <div>${escapeHtml(e.text)}</div>
          <div class="feed-asset">${escapeHtml(e.asset)}</div>
        </div>
      </div>
    `).join("");
  }

  function renderWatch() {
    const list = document.getElementById("watch-list");
    const watching = state.assets.filter((a) => (a.exposures || []).some((e) => e.severity === "watch"));
    if (!watching.length) {
      list.innerHTML = `<div class="empty">Nothing on the watch list. <span class="muted">No <code>watch</code>-severity exposures across any asset.</span></div>`;
      return;
    }
    list.innerHTML = watching.map(renderAssetCard).join("");
    list.querySelectorAll(".asset-card").forEach((card) => {
      card.addEventListener("click", () => openDrawer(card.dataset.id));
    });
  }

  // ─── drawer ────────────────────────────────────────────
  function openDrawer(id) {
    const a = state.assets.find((x) => x.asset?.id === id);
    if (!a) return;
    const inv = a.inventory || {};
    const ident = inv.identity || {};
    const dns = inv.dns || {};
    const tls = inv.tls || {};
    const http = inv.http || {};
    const waf = inv.waf || {};

    document.getElementById("drawer-title").textContent = a.asset?.value || a.asset?.id;
    document.getElementById("drawer-body").innerHTML = `
      ${section("Asset", kvTable([
        ["id", a.asset?.id],
        ["type", a.asset?.type],
        ["value", a.asset?.value],
        ["owner", a.asset?.owner],
        ["tags", (a.asset?.tags || []).join(", ")],
        ["notes", a.asset?.notes],
        ["discovered_via", a.asset?.discovered_via],
      ]))}

      ${section("Last scan", kvTable([
        ["scan id", a.scan?.id],
        ["started", a.scan?.started_at],
        ["completed", a.scan?.completed_at],
        ["duration", `${a.scan?.duration_seconds || 0}s`],
        ["tools run", (a.scan?.tools_run || []).join(", ")],
      ]))}

      ${section("Identity", kvTable([
        ["IPs", (ident.ip_addresses || []).join(", ") || "—"],
        ["ASN", ident.asn ? `${ident.asn} ${ident.asn_org || ""}` : "—"],
        ["registrar", ident.registrar || "—"],
        ["created", ident.whois_creation || "—"],
        ["expires", ident.whois_expiry || "—"],
        ["country", ident.geo?.country || "—"],
      ]))}

      ${section("DNS", kvTable([
        ["A", (dns.a || []).join(", ") || "—"],
        ["AAAA", (dns.aaaa || []).join(", ") || "—"],
        ["CNAME", dns.cname || "—"],
        ["MX", (dns.mx || []).map((m) => `${m.priority} ${m.host}`).join(", ") || "—"],
        ["NS", (dns.ns || []).join(", ") || "—"],
        ["SPF", dns.spf || "—"],
        ["DMARC", dns.dmarc || "—"],
        ["DNSSEC", dns.dnssec ? "enabled" : "disabled"],
      ]))}

      ${section("Subdomains", (inv.subdomains || []).length
        ? `<table class="kv-table">${(inv.subdomains || []).map((s) =>
            `<tr><td>${escapeHtml(s.name)}</td><td>${s.alive ? "alive" : "down"}</td></tr>`
          ).join("")}</table>`
        : "<div class='muted'>—</div>")}

      ${section("Open ports", (inv.ports || []).length
        ? `<table class="kv-table">${(inv.ports || []).map((p) => {
            const svc = (inv.services || []).find((s) => s.port === p.port);
            return `<tr><td>${p.port}/${p.protocol}</td><td>${escapeHtml(svc?.service || "?")}${svc?.banner ? ` <span class="muted">(${escapeHtml(svc.banner)})</span>` : ""}</td></tr>`;
          }).join("")}</table>`
        : "<div class='muted'>—</div>")}

      ${section("HTTP", kvTable([
        ["live", http.live ? "yes" : "no"],
        ["status", http.status_code],
        ["title", http.title],
        ["server", http.server],
        ["technologies", (http.technologies || []).map((t) => t.version ? `${t.name} ${t.version}` : t.name).join(", ") || "—"],
        ["headers missing", (http.headers_missing || []).join(", ") || "—"],
        ["cookies", (http.cookies || []).map((c) =>
          `${c.name}${c.secure ? " [secure]" : ""}${c.httponly ? " [httponly]" : ""}`
        ).join(", ") || "—"],
      ]))}

      ${section("TLS", kvTable([
        ["issuer", tls.issuer],
        ["subject", tls.subject],
        ["SAN", (tls.san || []).join(", ")],
        ["not before", tls.not_before],
        ["not after", tls.not_after],
        ["days to expiry", tls.days_until_expiry],
        ["protocols", (tls.protocols_supported || []).join(", ")],
        ["weak ciphers", (tls.weak_ciphers || []).join(", ") || "none"],
      ]))}

      ${section("WAF", kvTable([
        ["detected", waf.detected ? "yes" : "no"],
        ["vendor", waf.vendor],
        ["confidence", waf.confidence],
      ]))}

      ${section(`Exposures (${(a.exposures || []).length})`, (a.exposures || []).length
        ? (a.exposures || []).map((e) => `
            <div class="expo-row ${escapeAttr(e.severity)}">
              <div class="expo-title">${escapeHtml(e.title || e.type)}
                <span class="exposure-pill ${escapeAttr(e.severity)}" style="margin-left:8px;">${escapeHtml(e.severity || "")}</span>
              </div>
              <div class="expo-detail">${escapeHtml(e.detail || "")}</div>
              ${e.evidence ? `<div class="expo-evidence">${escapeHtml(e.evidence)}</div>` : ""}
            </div>
          `).join("")
        : "<div class='muted'>none</div>")}
    `;

    document.getElementById("drawer").classList.add("open");
    document.getElementById("drawer").setAttribute("aria-hidden", "false");
  }

  function closeDrawer() {
    const d = document.getElementById("drawer");
    d.classList.remove("open");
    d.setAttribute("aria-hidden", "true");
  }

  // ─── Add Target modal ──────────────────────────────────
  function openAddModal() {
    const m = document.getElementById("add-modal");
    m.classList.add("open");
    m.setAttribute("aria-hidden", "false");
    document.getElementById("add-form-feedback").hidden = true;
    document.getElementById("add-submit-btn").disabled = false;
    setTimeout(() => document.getElementById("t-value").focus(), 50);
  }

  function closeAddModal() {
    const m = document.getElementById("add-modal");
    m.classList.remove("open");
    m.setAttribute("aria-hidden", "true");
  }

  function updateTypeHelp() {
    const t = document.querySelector("input[name=\"type\"]:checked")?.value || "fqdn";
    const help = document.getElementById("t-type-help");
    const valueInput = document.getElementById("t-value");
    const placeholders = {
      fqdn: { help: "Single hostname — scans just this host (e.g. <code>www.example.com</code>)",                        ph: "www.example.com" },
      apex: { help: "Apex domain — enumerates all subdomains via passive sources, then deep-scans the apex itself",     ph: "example.com" },
      ip:   { help: "Single IPv4 — port + service + nuclei exposure templates. No DNS context",                         ph: "198.51.100.42" },
      cidr: { help: "CIDR range — naabu sweeps the range for live hosts. Use cautiously, rate-limit profile applies",   ph: "198.51.100.0/29" },
    };
    help.innerHTML = placeholders[t].help;
    valueInput.placeholder = placeholders[t].ph;

    // Different ID hint when CIDR / IP
    const idInput = document.getElementById("t-id");
    if (t === "ip" || t === "cidr") {
      idInput.placeholder = t === "ip" ? "host-198-51-100-42" : "range-198-51-100-0-29";
    } else {
      idInput.placeholder = "example-www";
    }
  }

  function autofillId() {
    const idInput = document.getElementById("t-id");
    if (idInput.dataset.touched === "true") return;
    const value = document.getElementById("t-value").value.trim().toLowerCase();
    const type  = document.querySelector("input[name=\"type\"]:checked")?.value || "fqdn";
    if (!value) { idInput.value = ""; return; }
    let id;
    if (type === "fqdn" || type === "apex") {
      id = value.replace(/^www\./, "").replace(/[^a-z0-9-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
    } else {
      id = value.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    }
    idInput.value = id.slice(0, 64);
  }

  // mark id as user-touched once they type into it
  document.addEventListener("DOMContentLoaded", () => {
    const idInput = document.getElementById("t-id");
    if (idInput) {
      idInput.addEventListener("input", () => { idInput.dataset.touched = "true"; });
    }
  });

  async function handleAddSubmit(e) {
    e.preventDefault();
    const submitBtn = document.getElementById("add-submit-btn");
    const feedback  = document.getElementById("add-form-feedback");
    feedback.hidden = false;
    feedback.className = "form-feedback info";
    feedback.textContent = "Submitting…";
    submitBtn.disabled = true;

    const form = e.target;
    const fd = new FormData(form);
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
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
      });
      const data = await r.json().catch(() => ({}));

      if (r.ok && data.ok) {
        feedback.className = "form-feedback ok";
        feedback.innerHTML = `Target <code>${escapeHtml(payload.id)}</code> added. Commit: <code>${escapeHtml((data.commit?.sha || "").slice(0, 7))}</code>. Scan will run within ~10 min on the next cron tick, or trigger manually via the GitHub Actions tab.`;
        // Reset form fields except scope_verified (require explicit re-attestation each time)
        form.reset();
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

  function section(title, body) {
    return `<div class="drawer-section"><h4>${escapeHtml(title)}</h4>${body}</div>`;
  }

  function kvTable(rows) {
    return `<table class="kv-table">${rows.map(([k, v]) =>
      `<tr><td>${escapeHtml(k)}</td><td>${v == null || v === "" ? "<span class='muted'>—</span>" : escapeHtml(String(v))}</td></tr>`
    ).join("")}</table>`;
  }

  // ─── helpers ───────────────────────────────────────────
  function formatRelTime(isoStr) {
    if (!isoStr) return "—";
    const t = new Date(isoStr).getTime();
    if (isNaN(t)) return isoStr;
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
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function escapeAttr(s) {
    return escapeHtml(s);
  }
})();
