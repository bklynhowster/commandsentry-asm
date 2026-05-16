#!/usr/bin/env python3
"""
build_preview.py — Generate a self-contained throwaway dashboard from JSONL.

Reads every JSONL file in --normalized-dir and produces a single HTML file
with the data embedded inline (so it opens cleanly from file:// without
needing a local HTTP server).

This is intentionally throwaway — Phase 3 builds the real SPA that reads
from Supabase. The preview's job is to let us SEE the canonical data and
validate what features the real dashboard will need.

Usage:
    python3 scripts/normalize/build_preview.py \
        --normalized-dir "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized" \
        --output         "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized/preview-dashboard.html"

Then open the HTML file directly in a browser.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>COMMANDsentry Preview — Merged Data View</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700&family=Inter:wght@400;450;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap">
<style>
  :root {
    --ink:         #0B1B2B;
    --ink-80:      rgba(11,27,43,0.80);
    --ink-60:      rgba(11,27,43,0.60);
    --ink-30:      rgba(11,27,43,0.30);
    --ink-10:      rgba(11,27,43,0.10);
    --canvas:      #EAE7DF;
    --paper:       #FBFAF6;
    --paper-rule:  #D7D2C2;
    --copper:      #C8632A;
    --copper-ink:  #8C3E10;
    --copper-soft: #F1E1D3;
    --ok:          #2F6B4F;
    --danger:      #B02A2A;
    --warn:        #B4751E;
    --notice:      rgba(11,27,43,0.60);
    --font-display:'Archivo','Helvetica Neue',Arial,sans-serif;
    --font-body:   'Inter','Helvetica Neue',Arial,sans-serif;
    --font-mono:   'JetBrains Mono',ui-monospace,'SF Mono',Menlo,monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: var(--font-body);
    background: var(--canvas);
    color: var(--ink);
    line-height: 1.5;
  }
  .top-nav {
    display: flex; align-items: center; gap: 24px;
    padding: 14px 24px;
    background: var(--ink);
    color: var(--paper);
    border-bottom: 2px solid var(--copper);
  }
  .brand {
    font-family: var(--font-display);
    font-weight: 700;
    font-size: 18px;
    letter-spacing: 0.5px;
  }
  .preview-tag {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 3px 8px;
    background: var(--copper);
    color: var(--ink);
    border-radius: 2px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .top-nav nav { display: flex; gap: 4px; margin-left: auto; }
  .top-nav button.tab {
    background: transparent;
    color: var(--paper);
    border: 1px solid transparent;
    font-family: var(--font-body);
    font-size: 13px;
    font-weight: 500;
    padding: 6px 14px;
    cursor: pointer;
    border-radius: 2px;
  }
  .top-nav button.tab.active { background: var(--copper); color: var(--ink); }
  .top-nav button.tab:hover:not(.active) { background: rgba(255,255,255,0.08); }

  main { padding: 24px; max-width: 1500px; margin: 0 auto; }
  h1 {
    font-family: var(--font-display);
    font-weight: 700;
    font-size: 24px;
    margin: 0 0 4px 0;
  }
  h2 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 18px;
    margin: 24px 0 8px 0;
  }
  .subtitle { color: var(--ink-60); font-size: 13px; margin-bottom: 24px; }

  .stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }
  .stat {
    background: var(--paper);
    border: 1px solid var(--paper-rule);
    padding: 14px 16px;
    border-radius: 2px;
  }
  .stat .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--ink-60); }
  .stat .val { font-family: var(--font-display); font-size: 28px; font-weight: 700; margin-top: 2px; }
  .stat .sub { font-size: 12px; color: var(--ink-60); margin-top: 2px; }

  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--paper);
    border: 1px solid var(--paper-rule);
    font-size: 13px;
  }
  th, td {
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid var(--ink-10);
  }
  th {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--ink-60);
    background: var(--canvas);
    cursor: pointer;
    user-select: none;
  }
  th:hover { color: var(--copper); }
  tr:hover { background: var(--copper-soft); }
  tr.row-clickable { cursor: pointer; }
  td.mono { font-family: var(--font-mono); font-size: 12px; }
  td.num  { text-align: right; font-variant-numeric: tabular-nums; }

  .sev {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    padding: 2px 6px;
    border-radius: 2px;
    letter-spacing: 0.5px;
  }
  .sev-CRITICAL      { background: var(--danger); color: white; }
  .sev-HIGH          { background: #d96344; color: white; }
  .sev-MODERATE-HIGH { background: #d18840; color: white; }
  .sev-MODERATE      { background: var(--warn); color: white; }
  .sev-LOW           { background: var(--ok); color: white; }
  .sev-INFO          { background: var(--ink-30); color: var(--ink); }

  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 12px;
  }
  .filters input, .filters select {
    font-family: var(--font-body);
    font-size: 13px;
    padding: 6px 10px;
    border: 1px solid var(--paper-rule);
    background: var(--paper);
    border-radius: 2px;
  }
  .filters input { min-width: 240px; }

  .status-tag {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 2px;
    background: var(--ink-10);
    color: var(--ink);
  }
  .status-open                 { background: var(--danger); color: white; }
  .status-confirmed            { background: #d96344; color: white; }
  .status-detected             { background: var(--warn); color: white; }
  .status-regressed            { background: var(--danger); color: white; }
  .status-remediated           { background: var(--ok); color: white; }
  .status-validated_remediated { background: var(--ok); color: white; }

  .empty {
    padding: 32px;
    text-align: center;
    color: var(--ink-60);
    background: var(--paper);
    border: 1px dashed var(--paper-rule);
    border-radius: 2px;
  }

  .panel {
    background: var(--paper);
    border: 1px solid var(--paper-rule);
    padding: 16px;
    border-radius: 2px;
    margin-bottom: 12px;
  }
  .panel h3 {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 14px;
    margin: 0 0 8px 0;
  }
  .kv { display: flex; gap: 6px; font-size: 12px; }
  .kv .k { color: var(--ink-60); min-width: 120px; }
  .kv .v { font-family: var(--font-mono); }
  .org-tag {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 10px;
    padding: 2px 6px;
    background: var(--ink-10);
    color: var(--ink);
    border-radius: 2px;
  }
  .stub-tag {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 10px;
    padding: 2px 6px;
    background: var(--copper-soft);
    color: var(--copper-ink);
    border-radius: 2px;
    margin-left: 6px;
  }
  .back-link {
    display: inline-block;
    margin-bottom: 12px;
    color: var(--copper-ink);
    text-decoration: none;
    font-size: 13px;
    cursor: pointer;
  }
  .back-link:hover { text-decoration: underline; }
</style>
</head>
<body>

<header class="top-nav">
  <div class="brand">COMMANDsentry</div>
  <span class="preview-tag">Preview · Throwaway</span>
  <nav>
    <button class="tab active" data-view="assets">Assets</button>
    <button class="tab" data-view="findings">Findings</button>
    <button class="tab" data-view="services">Services</button>
    <button class="tab" data-view="severity">By Severity</button>
  </nav>
</header>

<main id="app"></main>

<script>
  // ─── data (embedded by build_preview.py) ─────────────────────────────────
  const DATA = __DATA_PLACEHOLDER__;

  // ─── state ───────────────────────────────────────────────────────────────
  let currentView = 'assets';
  let currentAsset = null;
  let findingsFilter = { q: '', severity: '', source: '', status: '' };

  // ─── helpers ─────────────────────────────────────────────────────────────
  function el(tag, attrs, children) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') e.className = v;
      else if (k === 'html') e.innerHTML = v;
      else if (k.startsWith('on')) e[k] = v;
      else e.setAttribute(k, v);
    }
    if (children) for (const c of children) {
      if (typeof c === 'string') e.appendChild(document.createTextNode(c));
      else if (c) e.appendChild(c);
    }
    return e;
  }

  function sevBadge(s) { return el('span', {class: `sev sev-${s}`}, [s]); }
  function statusBadge(s) { return el('span', {class: `status-tag status-${s}`}, [s || 'unknown']); }
  function escapeHtml(s) { return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  function findingsByAsset(aid) {
    return DATA.findings.filter(f => f.asset_id === aid);
  }
  function subdomainsByAsset(aid) {
    return DATA.subdomains.filter(s => s.asset_id === aid);
  }
  function servicesByAsset(aid) {
    return DATA.services.filter(s => s.asset_id === aid);
  }
  function severityCounts(findings) {
    const counts = {CRITICAL:0, HIGH:0, 'MODERATE-HIGH':0, MODERATE:0, LOW:0, INFO:0};
    for (const f of findings) {
      if (counts.hasOwnProperty(f.severity)) counts[f.severity]++;
    }
    return counts;
  }

  // ─── view: ASSETS ────────────────────────────────────────────────────────
  function renderAssets() {
    const app = document.getElementById('app');
    app.innerHTML = '';

    app.appendChild(el('h1', null, ['Assets']));
    app.appendChild(el('div', {class: 'subtitle'}, [
      `${DATA.assets.length} assets · ${DATA.findings.length} findings · ${DATA.services.length} services`
    ]));

    // Stat cards — fleet rollup
    const sevTotal = severityCounts(DATA.findings);
    const grid = el('div', {class: 'stat-grid'});
    grid.appendChild(stat('CRITICAL', sevTotal.CRITICAL, 'open findings'));
    grid.appendChild(stat('HIGH', sevTotal.HIGH, 'open findings'));
    grid.appendChild(stat('MODERATE', sevTotal.MODERATE + sevTotal['MODERATE-HIGH'], 'open findings'));
    grid.appendChild(stat('LOW', sevTotal.LOW, 'open findings'));
    grid.appendChild(stat('Assets', DATA.assets.length, `${DATA.assets.filter(a => a.source === 'synthesized_from_findings').length} synthesized stubs`));
    grid.appendChild(stat('Services exposed', DATA.services.length, 'across all assets'));
    app.appendChild(grid);

    // Asset table
    const tbl = el('table');
    const thead = el('thead');
    thead.appendChild(el('tr', null, [
      el('th', null, ['Asset']),
      el('th', null, ['Org']),
      el('th', null, ['Type']),
      el('th', {class: 'num'}, ['Subs']),
      el('th', {class: 'num'}, ['Services']),
      el('th', {class: 'num'}, ['C']),
      el('th', {class: 'num'}, ['H']),
      el('th', {class: 'num'}, ['M']),
      el('th', {class: 'num'}, ['L']),
      el('th', {class: 'num'}, ['I']),
    ]));
    tbl.appendChild(thead);

    const tbody = el('tbody');
    // Sort: most severe first
    const sortedAssets = [...DATA.assets].sort((a, b) => {
      const af = findingsByAsset(a.asset_id);
      const bf = findingsByAsset(b.asset_id);
      const ac = severityCounts(af);
      const bc = severityCounts(bf);
      const score = c => c.CRITICAL*1e6 + c.HIGH*1e4 + (c.MODERATE+c['MODERATE-HIGH'])*100 + c.LOW;
      return score(bc) - score(ac);
    });

    for (const a of sortedAssets) {
      const f = findingsByAsset(a.asset_id);
      const c = severityCounts(f);
      const subs = subdomainsByAsset(a.asset_id);
      const svcs = servicesByAsset(a.asset_id);
      const stub = a.source === 'synthesized_from_findings';
      const nameCell = el('td', {class: 'mono'}, [a.asset_id]);
      if (stub) nameCell.appendChild(el('span', {class: 'stub-tag'}, ['not in ASM']));
      const row = el('tr', {class: 'row-clickable', onclick: () => { currentAsset = a.asset_id; currentView = 'asset-detail'; render(); }}, [
        nameCell,
        el('td', null, [el('span', {class: 'org-tag'}, [a.organization || 'unknown'])]),
        el('td', {class: 'mono'}, [a.type || '']),
        el('td', {class: 'num'}, [String(subs.length)]),
        el('td', {class: 'num'}, [String(svcs.length)]),
        el('td', {class: 'num'}, [c.CRITICAL ? String(c.CRITICAL) : '–']),
        el('td', {class: 'num'}, [c.HIGH ? String(c.HIGH) : '–']),
        el('td', {class: 'num'}, [String(c.MODERATE + c['MODERATE-HIGH']) === '0' ? '–' : String(c.MODERATE + c['MODERATE-HIGH'])]),
        el('td', {class: 'num'}, [c.LOW ? String(c.LOW) : '–']),
        el('td', {class: 'num'}, [c.INFO ? String(c.INFO) : '–']),
      ]);
      tbody.appendChild(row);
    }
    tbl.appendChild(tbody);
    app.appendChild(tbl);
  }

  function stat(label, value, sub) {
    return el('div', {class: 'stat'}, [
      el('div', {class: 'lbl'}, [label]),
      el('div', {class: 'val'}, [String(value)]),
      el('div', {class: 'sub'}, [sub || '']),
    ]);
  }

  // ─── view: ASSET DETAIL ──────────────────────────────────────────────────
  function renderAssetDetail() {
    const app = document.getElementById('app');
    app.innerHTML = '';

    const a = DATA.assets.find(x => x.asset_id === currentAsset);
    if (!a) { app.innerHTML = '<p>Asset not found.</p>'; return; }

    app.appendChild(el('a', {class: 'back-link', onclick: () => { currentView = 'assets'; render(); }}, ['← All Assets']));
    app.appendChild(el('h1', null, [a.asset_id]));
    const subt = [`${a.type || ''} · ${a.organization || 'unknown'}`];
    if (a.source === 'synthesized_from_findings') subt.push(' · not tracked in ASM');
    app.appendChild(el('div', {class: 'subtitle'}, subt));

    const f = findingsByAsset(a.asset_id);
    const c = severityCounts(f);
    const grid = el('div', {class: 'stat-grid'});
    grid.appendChild(stat('CRITICAL', c.CRITICAL, ''));
    grid.appendChild(stat('HIGH', c.HIGH, ''));
    grid.appendChild(stat('MODERATE', c.MODERATE + c['MODERATE-HIGH'], ''));
    grid.appendChild(stat('LOW', c.LOW, ''));
    grid.appendChild(stat('INFO', c.INFO, ''));
    app.appendChild(grid);

    // Subdomains panel
    const subs = subdomainsByAsset(a.asset_id);
    if (subs.length) {
      app.appendChild(el('h2', null, ['Subdomains']));
      const tbl = el('table');
      tbl.appendChild(el('thead', null, [el('tr', null, [
        el('th', null, ['Name']),
        el('th', null, ['Alive']),
        el('th', null, ['Platform']),
        el('th', null, ['WAF']),
        el('th', null, ['Server']),
      ])]));
      const tb = el('tbody');
      for (const s of subs) {
        const waf = s.waf && s.waf.detected ? `${s.waf.vendor||'detected'}` : '–';
        tb.appendChild(el('tr', null, [
          el('td', {class: 'mono'}, [s.name]),
          el('td', null, [s.alive ? '✓' : '–']),
          el('td', null, [s.platform_label || '']),
          el('td', null, [waf]),
          el('td', {class: 'mono'}, [s.server || '']),
        ]));
      }
      tbl.appendChild(tb);
      app.appendChild(tbl);
    }

    // Services panel
    const svcs = servicesByAsset(a.asset_id);
    if (svcs.length) {
      app.appendChild(el('h2', null, [`Services (${svcs.length})`]));
      const tbl = el('table');
      tbl.appendChild(el('thead', null, [el('tr', null, [
        el('th', null, ['Subdomain']),
        el('th', null, ['IP']),
        el('th', {class: 'num'}, ['Port']),
        el('th', null, ['Proto']),
        el('th', null, ['Service']),
        el('th', null, ['TLS']),
      ])]));
      const tb = el('tbody');
      for (const s of svcs) {
        tb.appendChild(el('tr', null, [
          el('td', {class: 'mono'}, [s.subdomain]),
          el('td', {class: 'mono'}, [s.host_ip]),
          el('td', {class: 'num'}, [String(s.port)]),
          el('td', {class: 'mono'}, [s.protocol || '']),
          el('td', null, [s.service || '']),
          el('td', null, [s.tls ? '✓' : '–']),
        ]));
      }
      tbl.appendChild(tb);
      app.appendChild(tbl);
    }

    // Findings panel — sorted by severity
    if (f.length) {
      app.appendChild(el('h2', null, [`Findings (${f.length})`]));
      const sevOrder = ['CRITICAL','HIGH','MODERATE-HIGH','MODERATE','LOW','INFO'];
      const sortedF = [...f].sort((x, y) => sevOrder.indexOf(x.severity) - sevOrder.indexOf(y.severity));
      const tbl = el('table');
      tbl.appendChild(el('thead', null, [el('tr', null, [
        el('th', null, ['Sev']),
        el('th', null, ['Title']),
        el('th', null, ['Source']),
        el('th', null, ['Status']),
        el('th', null, ['Subdomain']),
      ])]));
      const tb = el('tbody');
      for (const x of sortedF.slice(0, 500)) {
        tb.appendChild(el('tr', null, [
          el('td', null, [sevBadge(x.severity)]),
          el('td', null, [x.title.slice(0, 120)]),
          el('td', {class: 'mono'}, [x.source]),
          el('td', null, [statusBadge(x.current_status)]),
          el('td', {class: 'mono'}, [x.subdomain || '']),
        ]));
      }
      tbl.appendChild(tb);
      app.appendChild(tbl);
      if (f.length > 500) app.appendChild(el('div', {class: 'subtitle'}, [`(showing first 500 of ${f.length})`]));
    }
  }

  // ─── view: FINDINGS ──────────────────────────────────────────────────────
  function renderFindings() {
    const app = document.getElementById('app');
    app.innerHTML = '';
    app.appendChild(el('h1', null, ['Findings']));
    app.appendChild(el('div', {class: 'subtitle'}, [`${DATA.findings.length} unique findings across ${DATA.assets.length} assets`]));

    // Filters
    const filters = el('div', {class: 'filters'});
    const q = el('input', {placeholder: 'search title / asset_id / CVE...', value: findingsFilter.q});
    q.oninput = e => { findingsFilter.q = e.target.value.toLowerCase(); refresh(); };
    filters.appendChild(q);

    const sevSel = el('select');
    for (const s of ['', 'CRITICAL', 'HIGH', 'MODERATE-HIGH', 'MODERATE', 'LOW', 'INFO']) {
      const o = el('option', {value: s}, [s || 'all severities']);
      if (s === findingsFilter.severity) o.setAttribute('selected', 'selected');
      sevSel.appendChild(o);
    }
    sevSel.onchange = e => { findingsFilter.severity = e.target.value; refresh(); };
    filters.appendChild(sevSel);

    const srcSel = el('select');
    const srcs = [...new Set(DATA.findings.map(f => f.source))].sort();
    srcSel.appendChild(el('option', {value: ''}, ['all sources']));
    for (const s of srcs) srcSel.appendChild(el('option', {value: s}, [s]));
    srcSel.value = findingsFilter.source;
    srcSel.onchange = e => { findingsFilter.source = e.target.value; refresh(); };
    filters.appendChild(srcSel);

    const statSel = el('select');
    statSel.appendChild(el('option', {value: ''}, ['all statuses']));
    for (const s of ['detected','confirmed','open','regressed','remediated','validated_remediated','false_positive']) {
      statSel.appendChild(el('option', {value: s}, [s]));
    }
    statSel.value = findingsFilter.status;
    statSel.onchange = e => { findingsFilter.status = e.target.value; refresh(); };
    filters.appendChild(statSel);

    app.appendChild(filters);

    // Table
    const tblWrap = el('div');
    app.appendChild(tblWrap);

    function refresh() {
      tblWrap.innerHTML = '';
      const filtered = DATA.findings.filter(f => {
        if (findingsFilter.severity && f.severity !== findingsFilter.severity) return false;
        if (findingsFilter.source   && f.source   !== findingsFilter.source) return false;
        if (findingsFilter.status   && f.current_status !== findingsFilter.status) return false;
        if (findingsFilter.q) {
          const q = findingsFilter.q;
          const blob = (f.title + ' ' + f.asset_id + ' ' + (f.cve||[]).join(',') + ' ' + (f.description||'')).toLowerCase();
          if (!blob.includes(q)) return false;
        }
        return true;
      });
      tblWrap.appendChild(el('div', {class: 'subtitle'}, [`${filtered.length} matching`]));
      const tbl = el('table');
      tbl.appendChild(el('thead', null, [el('tr', null, [
        el('th', null, ['Sev']),
        el('th', null, ['Asset']),
        el('th', null, ['Title']),
        el('th', null, ['Source']),
        el('th', null, ['Status']),
        el('th', null, ['Category']),
        el('th', null, ['First detected']),
      ])]));
      const tb = el('tbody');
      const sevOrder = ['CRITICAL','HIGH','MODERATE-HIGH','MODERATE','LOW','INFO'];
      const sorted = [...filtered].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
      for (const f of sorted.slice(0, 1000)) {
        const row = el('tr', {class: 'row-clickable', onclick: () => { currentAsset = f.asset_id; currentView = 'asset-detail'; render(); }}, [
          el('td', null, [sevBadge(f.severity)]),
          el('td', {class: 'mono'}, [f.asset_id]),
          el('td', null, [f.title.slice(0, 100)]),
          el('td', {class: 'mono'}, [f.source]),
          el('td', null, [statusBadge(f.current_status)]),
          el('td', {class: 'mono'}, [f.category || '']),
          el('td', {class: 'mono'}, [(f.first_detected_at || '').slice(0, 10)]),
        ]);
        tb.appendChild(row);
      }
      tbl.appendChild(tb);
      tblWrap.appendChild(tbl);
      if (sorted.length > 1000) tblWrap.appendChild(el('div', {class: 'subtitle'}, [`(showing first 1000 of ${sorted.length})`]));
    }
    refresh();
  }

  // ─── view: SERVICES ──────────────────────────────────────────────────────
  function renderServices() {
    const app = document.getElementById('app');
    app.innerHTML = '';
    app.appendChild(el('h1', null, ['Services']));
    app.appendChild(el('div', {class: 'subtitle'}, [`${DATA.services.length} services across the fleet`]));

    // Group by port
    const byPort = {};
    for (const s of DATA.services) {
      const key = `${s.port}/${s.protocol||'?'}`;
      if (!byPort[key]) byPort[key] = [];
      byPort[key].push(s);
    }

    app.appendChild(el('h2', null, ['By port']));
    const portTbl = el('table');
    portTbl.appendChild(el('thead', null, [el('tr', null, [
      el('th', null, ['Port/Proto']),
      el('th', {class: 'num'}, ['Count']),
      el('th', null, ['Service']),
      el('th', null, ['Assets exposing this']),
    ])]));
    const portTb = el('tbody');
    const portKeys = Object.keys(byPort).sort((a, b) => byPort[b].length - byPort[a].length);
    for (const k of portKeys) {
      const recs = byPort[k];
      const assets = [...new Set(recs.map(r => r.asset_id))];
      const services = [...new Set(recs.map(r => r.service).filter(Boolean))];
      portTb.appendChild(el('tr', null, [
        el('td', {class: 'mono'}, [k]),
        el('td', {class: 'num'}, [String(recs.length)]),
        el('td', null, [services.join(', ') || '–']),
        el('td', {class: 'mono'}, [assets.slice(0, 8).join(', ') + (assets.length > 8 ? ` +${assets.length-8}` : '')]),
      ]));
    }
    portTbl.appendChild(portTb);
    app.appendChild(portTbl);

    // All services flat
    app.appendChild(el('h2', null, [`All services (${DATA.services.length})`]));
    const tbl = el('table');
    tbl.appendChild(el('thead', null, [el('tr', null, [
      el('th', null, ['Asset']),
      el('th', null, ['Subdomain']),
      el('th', null, ['IP']),
      el('th', {class: 'num'}, ['Port']),
      el('th', null, ['Proto']),
      el('th', null, ['Service']),
      el('th', null, ['TLS']),
    ])]));
    const tb = el('tbody');
    for (const s of DATA.services) {
      tb.appendChild(el('tr', null, [
        el('td', {class: 'mono'}, [s.asset_id]),
        el('td', {class: 'mono'}, [s.subdomain]),
        el('td', {class: 'mono'}, [s.host_ip]),
        el('td', {class: 'num'}, [String(s.port)]),
        el('td', {class: 'mono'}, [s.protocol || '']),
        el('td', null, [s.service || '']),
        el('td', null, [s.tls ? '✓' : '–']),
      ]));
    }
    tbl.appendChild(tb);
    app.appendChild(tbl);
  }

  // ─── view: BY SEVERITY ───────────────────────────────────────────────────
  function renderBySeverity() {
    const app = document.getElementById('app');
    app.innerHTML = '';
    app.appendChild(el('h1', null, ['By Severity']));
    app.appendChild(el('div', {class: 'subtitle'}, ['Open findings grouped by tier — what needs attention first']));

    const sevOrder = ['CRITICAL','HIGH','MODERATE-HIGH','MODERATE','LOW','INFO'];
    for (const sev of sevOrder) {
      const matches = DATA.findings.filter(f => f.severity === sev);
      if (!matches.length) continue;
      const open = matches.filter(f => !['remediated','validated_remediated','false_positive'].includes(f.current_status));
      app.appendChild(el('h2', null, [sevBadge(sev), ` ${sev} (${matches.length})`]));
      app.appendChild(el('div', {class: 'subtitle'}, [`${open.length} open / ${matches.length - open.length} resolved or false-positive`]));

      const tbl = el('table');
      tbl.appendChild(el('thead', null, [el('tr', null, [
        el('th', null, ['Asset']),
        el('th', null, ['Title']),
        el('th', null, ['Source']),
        el('th', null, ['Status']),
      ])]));
      const tb = el('tbody');
      for (const f of matches.slice(0, 200)) {
        tb.appendChild(el('tr', {class: 'row-clickable', onclick: () => { currentAsset = f.asset_id; currentView = 'asset-detail'; render(); }}, [
          el('td', {class: 'mono'}, [f.asset_id]),
          el('td', null, [f.title.slice(0, 100)]),
          el('td', {class: 'mono'}, [f.source]),
          el('td', null, [statusBadge(f.current_status)]),
        ]));
      }
      tbl.appendChild(tb);
      app.appendChild(tbl);
    }
  }

  // ─── router ──────────────────────────────────────────────────────────────
  function render() {
    document.querySelectorAll('.tab').forEach(b => {
      b.classList.toggle('active', b.dataset.view === currentView || (currentView === 'asset-detail' && b.dataset.view === 'assets'));
    });
    if (currentView === 'assets') renderAssets();
    else if (currentView === 'asset-detail') renderAssetDetail();
    else if (currentView === 'findings') renderFindings();
    else if (currentView === 'services') renderServices();
    else if (currentView === 'severity') renderBySeverity();
  }

  document.querySelectorAll('.tab').forEach(b => {
    b.addEventListener('click', () => {
      currentView = b.dataset.view;
      currentAsset = null;
      render();
    });
  });

  render();
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--normalized-dir", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    nd = Path(args.normalized_dir).expanduser().resolve()
    out = Path(args.output).expanduser().resolve()

    data = {
        "assets":     load_jsonl(nd / "assets.jsonl"),
        "subdomains": load_jsonl(nd / "subdomains.jsonl"),
        "services":   load_jsonl(nd / "services.jsonl"),
        "findings":   load_jsonl(nd / "findings.jsonl"),
        "asm_scans":  load_jsonl(nd / "asm_scans.jsonl"),
    }

    html = HTML_TEMPLATE.replace("__DATA_PLACEHOLDER__", json.dumps(data, separators=(",", ":")))
    out.write_text(html)

    print(f"Built preview dashboard: {out}")
    print(f"  Assets:     {len(data['assets']):>5}")
    print(f"  Subdomains: {len(data['subdomains']):>5}")
    print(f"  Services:   {len(data['services']):>5}")
    print(f"  Findings:   {len(data['findings']):>5}")
    print(f"  ASM scans:  {len(data['asm_scans']):>5}")
    print(f"  Size: {out.stat().st_size:,} bytes")
    print()
    print(f"Open in browser: file://{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
