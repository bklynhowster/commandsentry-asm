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

  /* Resolved findings get visually de-emphasized — the severity badge
     should not compete with open findings for attention. The data stays
     visible (engineer needs to see "was fixed on X date") but the row
     stops yelling. Phase 3 SPA principle: a remediated HIGH is not a HIGH
     for posture purposes; treat it visually accordingly. */
  tr.row-resolved { opacity: 0.5; }
  tr.row-resolved .sev { opacity: 0.6; }
  tr.row-resolved td { color: var(--ink-60); }

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

  /* Posture cards — the primary CISO-tier view */
  .posture-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
    gap: 12px;
  }
  .posture-card {
    background: var(--paper);
    border: 1px solid var(--paper-rule);
    border-left: 4px solid var(--ink-30);
    padding: 16px 18px;
    border-radius: 2px;
    cursor: pointer;
    transition: transform 0.05s, box-shadow 0.05s;
  }
  .posture-card:hover { transform: translateY(-1px); box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
  .posture-card.verdict-CRITICAL      { border-left-color: var(--danger); }
  .posture-card.verdict-HIGH          { border-left-color: #d96344; }
  .posture-card.verdict-MODERATE-HIGH { border-left-color: #d18840; }
  .posture-card.verdict-MODERATE      { border-left-color: var(--warn); }
  .posture-card.verdict-LOW           { border-left-color: var(--ok); }
  .posture-card.verdict-INFO          { border-left-color: var(--ink-30); }
  .posture-card.verdict-UNKNOWN       { border-left-color: var(--ink-10); }

  .posture-head {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    margin-bottom: 4px;
  }
  .posture-name {
    font-family: var(--font-mono);
    font-size: 14px;
    font-weight: 600;
    color: var(--ink);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .posture-reason {
    font-size: 13px;
    color: var(--ink-80);
    line-height: 1.45;
    margin: 6px 0;
  }
  .posture-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
    font-size: 11px;
    color: var(--ink-60);
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--ink-10);
  }
  .posture-meta .meta-item { display: flex; gap: 4px; align-items: center; }
  .posture-meta .meta-item .lbl { text-transform: uppercase; letter-spacing: 0.5px; }
  .posture-meta .meta-item .num { font-family: var(--font-mono); font-weight: 600; color: var(--ink); }
  .verdict-badge {
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 3px 8px;
    border-radius: 2px;
    white-space: nowrap;
  }
  .verdict-CRITICAL .verdict-badge      { background: var(--danger);     color: white; }
  .verdict-HIGH .verdict-badge          { background: #d96344;           color: white; }
  .verdict-MODERATE-HIGH .verdict-badge { background: #d18840;           color: white; }
  .verdict-MODERATE .verdict-badge      { background: var(--warn);       color: white; }
  .verdict-LOW .verdict-badge           { background: var(--ok);         color: white; }
  .verdict-INFO .verdict-badge          { background: var(--ink-30);     color: var(--ink); }
  .verdict-UNKNOWN .verdict-badge       { background: var(--ink-10);     color: var(--ink-60); }

  .posture-section-header {
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--ink-60);
    margin: 20px 0 8px 0;
  }
  .view-toggle {
    display: inline-flex;
    gap: 1px;
    background: var(--paper-rule);
    border-radius: 2px;
    padding: 1px;
    margin-bottom: 16px;
  }
  .view-toggle button {
    font-family: var(--font-body);
    font-size: 12px;
    font-weight: 500;
    padding: 5px 12px;
    border: 0;
    background: var(--paper);
    cursor: pointer;
    border-radius: 2px;
  }
  .view-toggle button.active { background: var(--ink); color: var(--paper); }
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
  let findingsFilter = { q: '', severity: '', source: '', status: '', showResolved: false };

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

  // ─── view: ASSETS (posture-card primary view) ────────────────────────────
  let assetsLayout = 'cards';  // 'cards' or 'table'

  const VERDICT_ORDER = ['CRITICAL','HIGH','MODERATE-HIGH','MODERATE','LOW','INFO','UNKNOWN'];
  const VERDICT_INDEX = Object.fromEntries(VERDICT_ORDER.map((v,i) => [v, i]));

  function renderAssets() {
    const app = document.getElementById('app');
    app.innerHTML = '';

    app.appendChild(el('h1', null, ['Posture']));
    app.appendChild(el('div', {class: 'subtitle'}, [
      'Per-asset risk verdicts. Click any card for details.'
    ]));

    // Fleet posture summary — counts of assets at each verdict tier
    const verdictCounts = {CRITICAL:0, HIGH:0, 'MODERATE-HIGH':0, MODERATE:0, LOW:0, INFO:0, UNKNOWN:0};
    for (const a of DATA.assets) {
      const v = a.current_risk || 'UNKNOWN';
      if (verdictCounts.hasOwnProperty(v)) verdictCounts[v]++;
    }
    const grid = el('div', {class: 'stat-grid'});
    if (verdictCounts.CRITICAL)      grid.appendChild(stat('CRITICAL',      verdictCounts.CRITICAL,      'assets'));
    if (verdictCounts.HIGH)          grid.appendChild(stat('HIGH',          verdictCounts.HIGH,          'assets'));
    if (verdictCounts['MODERATE-HIGH']) grid.appendChild(stat('MODERATE-HIGH', verdictCounts['MODERATE-HIGH'], 'assets'));
    if (verdictCounts.MODERATE)      grid.appendChild(stat('MODERATE',      verdictCounts.MODERATE,      'assets'));
    if (verdictCounts.LOW)           grid.appendChild(stat('LOW',           verdictCounts.LOW,           'assets'));
    if (verdictCounts.INFO)          grid.appendChild(stat('INFO',          verdictCounts.INFO,          'assets'));
    if (verdictCounts.UNKNOWN)       grid.appendChild(stat('UNKNOWN',       verdictCounts.UNKNOWN,       'never vuln-scanned'));
    app.appendChild(grid);

    // View toggle
    const toggle = el('div', {class: 'view-toggle'});
    const btnCards = el('button', {class: assetsLayout === 'cards' ? 'active' : '', onclick: () => { assetsLayout = 'cards'; renderAssets(); }}, ['Posture cards']);
    const btnTable = el('button', {class: assetsLayout === 'table' ? 'active' : '', onclick: () => { assetsLayout = 'table'; renderAssets(); }}, ['Detail table']);
    toggle.appendChild(btnCards);
    toggle.appendChild(btnTable);
    app.appendChild(toggle);

    // Sort assets by verdict severity, then by total open findings descending
    const sortedAssets = [...DATA.assets].sort((a, b) => {
      const va = VERDICT_INDEX[a.current_risk || 'UNKNOWN'] ?? 99;
      const vb = VERDICT_INDEX[b.current_risk || 'UNKNOWN'] ?? 99;
      if (va !== vb) return va - vb;
      return (b.open_findings_total || 0) - (a.open_findings_total || 0);
    });

    if (assetsLayout === 'cards') {
      renderPostureCards(app, sortedAssets);
    } else {
      renderAssetTable(app, sortedAssets);
    }
  }

  function renderPostureCards(app, assets) {
    // Group cards by verdict tier with section headers
    let currentVerdict = null;
    let currentGrid = null;
    for (const a of assets) {
      const v = a.current_risk || 'UNKNOWN';
      if (v !== currentVerdict) {
        currentVerdict = v;
        const sevDescriptor = {
          'CRITICAL': 'Critical — immediate attention',
          'HIGH': 'High — fix this week',
          'MODERATE-HIGH': 'Moderate-High — schedule remediation',
          'MODERATE': 'Moderate — track and plan',
          'LOW': 'Low — baseline hardening',
          'INFO': 'Informational only',
          'UNKNOWN': 'Not vulnerability-scanned yet',
        }[v] || v;
        app.appendChild(el('div', {class: 'posture-section-header'}, [sevDescriptor]));
        currentGrid = el('div', {class: 'posture-grid'});
        app.appendChild(currentGrid);
      }
      currentGrid.appendChild(makePostureCard(a));
    }
  }

  function makePostureCard(a) {
    const v = a.current_risk || 'UNKNOWN';
    const stub = a.source === 'synthesized_from_findings';
    const card = el('div', {
      class: `posture-card verdict-${v}`,
      onclick: () => { currentAsset = a.asset_id; currentView = 'asset-detail'; render(); }
    });

    const head = el('div', {class: 'posture-head'});
    const nameWrap = el('div', {class: 'posture-name'}, [a.asset_id]);
    head.appendChild(nameWrap);
    head.appendChild(el('span', {class: 'verdict-badge'}, [v]));
    card.appendChild(head);

    if (stub) {
      card.appendChild(el('div', {style: 'font-size:10px; font-family: var(--font-mono); color: var(--copper-ink); margin-top:-2px;'}, ['Not yet in COMMANDsentry ASM tracking']));
    }

    card.appendChild(el('div', {class: 'posture-reason'}, [a.current_risk_reason || 'No reason recorded.']));

    // Bottom meta row: open counts by severity + last observed
    const meta = el('div', {class: 'posture-meta'});
    const open = a.open_findings_by_severity || {};
    const openTotal = a.open_findings_total || 0;
    meta.appendChild(metaItem('Open', String(openTotal)));
    for (const sev of ['CRITICAL','HIGH','MODERATE-HIGH','MODERATE','LOW']) {
      if (open[sev]) meta.appendChild(metaItem(sev[0], String(open[sev])));  // single-letter shorthand
    }
    if (a.organization && a.organization !== 'unknown') {
      meta.appendChild(metaItem('Org', a.organization.replace(/_/g, ' ')));
    }
    if (a.last_observed) {
      meta.appendChild(metaItem('Last scan', (a.last_observed || '').slice(0, 10)));
    }
    card.appendChild(meta);

    return card;
  }

  function metaItem(label, value) {
    return el('div', {class: 'meta-item'}, [
      el('span', {class: 'lbl'}, [label]),
      el('span', {class: 'num'}, [value]),
    ]);
  }

  function renderAssetTable(app, assets) {
    const tbl = el('table');
    const thead = el('thead');
    thead.appendChild(el('tr', null, [
      el('th', null, ['Verdict']),
      el('th', null, ['Asset']),
      el('th', null, ['Reason']),
      el('th', null, ['Org']),
      el('th', {class: 'num'}, ['Open']),
      el('th', {class: 'num'}, ['Subs']),
      el('th', {class: 'num'}, ['Svcs']),
    ]));
    tbl.appendChild(thead);
    const tbody = el('tbody');
    for (const a of assets) {
      const v = a.current_risk || 'UNKNOWN';
      const subs = subdomainsByAsset(a.asset_id);
      const svcs = servicesByAsset(a.asset_id);
      const nameCell = el('td', {class: 'mono'}, [a.asset_id]);
      if (a.source === 'synthesized_from_findings') nameCell.appendChild(el('span', {class: 'stub-tag'}, ['not in ASM']));
      const row = el('tr', {class: 'row-clickable', onclick: () => { currentAsset = a.asset_id; currentView = 'asset-detail'; render(); }}, [
        el('td', null, [el('span', {class: 'verdict-badge', style: getVerdictBadgeStyle(v)}, [v])]),
        nameCell,
        el('td', null, [a.current_risk_reason || '']),
        el('td', null, [el('span', {class: 'org-tag'}, [a.organization || 'unknown'])]),
        el('td', {class: 'num'}, [String(a.open_findings_total || 0)]),
        el('td', {class: 'num'}, [String(subs.length)]),
        el('td', {class: 'num'}, [String(svcs.length)]),
      ]);
      tbody.appendChild(row);
    }
    tbl.appendChild(tbody);
    app.appendChild(tbl);
  }

  function getVerdictBadgeStyle(v) {
    const colors = {
      'CRITICAL': 'background:#B02A2A;color:white',
      'HIGH': 'background:#d96344;color:white',
      'MODERATE-HIGH': 'background:#d18840;color:white',
      'MODERATE': 'background:#B4751E;color:white',
      'LOW': 'background:#2F6B4F;color:white',
      'INFO': 'background:rgba(11,27,43,0.30);color:#0B1B2B',
      'UNKNOWN': 'background:rgba(11,27,43,0.10);color:rgba(11,27,43,0.60)',
    };
    return colors[v] || '';
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

    // Related assets — sibling cards sharing the registrable apex.
    // Provides quick navigation without mixing siblings' findings into THIS page.
    // (Subdomains and Services tables removed — they were ASM-tier surface
    // inventory that confused users when their findings didn't appear in the
    // findings list below. ASM data belongs on a separate Surface view.)
    const myParts = a.asset_id.split('.');
    const myApex = myParts.length >= 2 ? myParts.slice(-2).join('.') : a.asset_id;
    const siblings = DATA.assets.filter(x =>
      x.asset_id !== a.asset_id &&
      !x.asset_id.startsWith('ip:') &&
      (x.asset_id === myApex || x.asset_id.endsWith('.' + myApex))
    ).sort((x, y) => x.asset_id.localeCompare(y.asset_id));

    if (siblings.length > 0) {
      app.appendChild(el('h2', null, ['Related assets']));
      app.appendChild(el('div', {class: 'subtitle'}, [
        `Other assets sharing the ${myApex} apex. Click to view their findings independently.`
      ]));
      const relGrid = el('div', {class: 'posture-grid'});
      for (const s of siblings) {
        relGrid.appendChild(makePostureCard(s));
      }
      app.appendChild(relGrid);
    }

    // Findings panel — OPEN findings shown by default; resolved/historical
    // findings hidden under an expandable section. Howie's design principle:
    // the dashboard should surface what needs attention, not enumerate history.
    if (f.length) {
      const sevOrder = ['CRITICAL','HIGH','MODERATE-HIGH','MODERATE','LOW','INFO'];
      const RESOLVED = new Set(['remediated','validated_remediated','false_positive','wont_fix','accepted_risk']);
      const open_findings = f.filter(x => !RESOLVED.has(x.current_status));
      const resolved_findings = f.filter(x => RESOLVED.has(x.current_status));

      open_findings.sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
      resolved_findings.sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

      app.appendChild(el('h2', null, [`Open findings (${open_findings.length})`]));
      if (open_findings.length === 0) {
        app.appendChild(el('div', {class: 'empty'}, ['No open findings on this asset. ✓']));
      } else {
        const tbl = el('table');
        tbl.appendChild(el('thead', null, [el('tr', null, [
          el('th', null, ['Sev']),
          el('th', null, ['Title']),
          el('th', null, ['Source']),
          el('th', null, ['Status']),
          el('th', null, ['Subdomain']),
        ])]));
        const tb = el('tbody');
        for (const x of open_findings.slice(0, 500)) {
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
        if (open_findings.length > 500) app.appendChild(el('div', {class: 'subtitle'}, [`(showing first 500 of ${open_findings.length})`]));
      }

      // Resolved history — collapsed by default, expand on click
      if (resolved_findings.length > 0) {
        const details = el('details', {style: 'margin-top: 20px;'});
        const summary = el('summary', {style: 'cursor: pointer; font-family: var(--font-display); font-weight: 600; font-size: 14px; color: var(--ink-60); padding: 8px 0;'}, [
          `Remediation history (${resolved_findings.length} resolved finding${resolved_findings.length !== 1 ? 's' : ''}) — click to expand`
        ]);
        details.appendChild(summary);
        const tbl = el('table', {style: 'margin-top: 8px;'});
        tbl.appendChild(el('thead', null, [el('tr', null, [
          el('th', null, ['Sev (then)']),
          el('th', null, ['Title']),
          el('th', null, ['Source']),
          el('th', null, ['Status']),
          el('th', null, ['Resolved']),
        ])]));
        const tb = el('tbody');
        for (const x of resolved_findings) {
          tb.appendChild(el('tr', {class: 'row-resolved'}, [
            el('td', null, [sevBadge(x.severity)]),
            el('td', null, [x.title.slice(0, 120)]),
            el('td', {class: 'mono'}, [x.source]),
            el('td', null, [statusBadge(x.current_status)]),
            el('td', {class: 'mono'}, [(x.remediated_at || x.last_observed_at || '').slice(0, 10)]),
          ]));
        }
        tbl.appendChild(tb);
        details.appendChild(tbl);
        app.appendChild(details);
      }
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
    for (const s of ['open','regressed','remediated','validated_remediated','false_positive']) {
      statSel.appendChild(el('option', {value: s}, [s]));
    }
    statSel.value = findingsFilter.status;
    statSel.onchange = e => { findingsFilter.status = e.target.value; refresh(); };
    filters.appendChild(statSel);

    // "Show resolved" toggle — hidden by default
    const resLabel = el('label', {style: 'display:flex; align-items:center; gap:6px; font-size:13px; color: var(--ink-60); padding: 0 6px;'});
    const resCb = el('input', {type: 'checkbox'});
    if (findingsFilter.showResolved) resCb.setAttribute('checked', 'checked');
    resCb.onchange = e => { findingsFilter.showResolved = e.target.checked; refresh(); };
    resLabel.appendChild(resCb);
    resLabel.appendChild(el('span', null, ['Show resolved']));
    filters.appendChild(resLabel);

    app.appendChild(filters);

    // Table
    const tblWrap = el('div');
    app.appendChild(tblWrap);

    function refresh() {
      tblWrap.innerHTML = '';
      const RESOLVED = new Set(['remediated','validated_remediated','false_positive','wont_fix','accepted_risk']);
      const filtered = DATA.findings.filter(f => {
        // Hide resolved by default unless toggle is on OR user explicitly filtered to a resolved status
        if (!findingsFilter.showResolved && !findingsFilter.status && RESOLVED.has(f.current_status)) return false;
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
      const sorted = [...filtered].sort((a, b) => {
        const aRes = RESOLVED.has(a.current_status) ? 1 : 0;
        const bRes = RESOLVED.has(b.current_status) ? 1 : 0;
        if (aRes !== bRes) return aRes - bRes;
        return sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity);
      });
      for (const f of sorted.slice(0, 1000)) {
        const isResolved = RESOLVED.has(f.current_status);
        const row = el('tr', {class: 'row-clickable' + (isResolved ? ' row-resolved' : ''), onclick: () => { currentAsset = f.asset_id; currentView = 'asset-detail'; render(); }}, [
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
      const RESOLVED = new Set(['remediated','validated_remediated','false_positive','wont_fix','accepted_risk']);
      // Sort open first, resolved last
      const sortedMatches = [...matches].sort((a, b) => {
        const aRes = RESOLVED.has(a.current_status) ? 1 : 0;
        const bRes = RESOLVED.has(b.current_status) ? 1 : 0;
        return aRes - bRes;
      });
      for (const f of sortedMatches.slice(0, 200)) {
        const isResolved = RESOLVED.has(f.current_status);
        tb.appendChild(el('tr', {class: 'row-clickable' + (isResolved ? ' row-resolved' : ''), onclick: () => { currentAsset = f.asset_id; currentView = 'asset-detail'; render(); }}, [
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
