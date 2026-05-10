/**
 * COMMANDsentry — bulk-add-targets Netlify Function
 * ──────────────────────────────────────────────────
 * Receives N targets in a single request, validates each one, appends them
 * all to data/targets.yml in one commit. The single push triggers the
 * asm-discover workflow which scans the diff (all newly-added IDs).
 *
 * Body shape:
 *   {
 *     attest: true,
 *     targets: [
 *       { id, type, value, owner?, tags?, notes? },
 *       ...
 *     ]
 *   }
 *
 * Returns:
 *   { ok: true, added_count, target_ids[], commit: {sha, url}, skipped: [...] }
 *
 * Auth model: same as /api/add-target — Netlify password protection guards entry,
 * one batch-level attestation covers all targets in the request.
 *
 * Env vars: GITHUB_TOKEN, GITHUB_REPO, GITHUB_BRANCH (defaults to "main").
 */

const yaml = require('js-yaml');

// ─── Validation rules (kept in sync with add-target.js) ──────────
const TARGET_TYPES = ['fqdn', 'apex', 'ip', 'cidr'];
const ID_PATTERN     = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
const FQDN_PATTERN   = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
const IPV4_PATTERN   = /^(\d{1,3}\.){3}\d{1,3}$/;
const CIDR_PATTERN   = /^(\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[1-2]\d|3[0-2])$/;
const SLUG_TAG       = /^[a-z0-9][a-z0-9-]{0,30}$/i;

const MAX_BATCH = 100;  // sanity cap — prevents accidental 10k-row CSV from spamming the queue

function isValidIp(s) {
  if (!IPV4_PATTERN.test(s)) return false;
  return s.split('.').every(o => Number(o) >= 0 && Number(o) <= 255);
}
function isValidCidr(s) {
  if (!CIDR_PATTERN.test(s)) return false;
  const [ip] = s.split('/');
  return isValidIp(ip);
}

function validateTarget(t, idx) {
  const errors = [];
  const prefix = `target[${idx}]`;
  if (!t || typeof t !== 'object') return [`${prefix}: must be an object`];
  if (!t.id || !ID_PATTERN.test(t.id)) {
    errors.push(`${prefix}: id "${t.id || ''}" must be lowercase letters/digits/hyphens, 3-64 chars, no leading/trailing hyphen`);
  }
  if (!TARGET_TYPES.includes(t.type)) {
    errors.push(`${prefix}: type must be one of: ${TARGET_TYPES.join(', ')}`);
  }
  if (!t.value || typeof t.value !== 'string') {
    errors.push(`${prefix}: value is required`);
  } else {
    const v = t.value.trim().toLowerCase();
    if (t.type === 'fqdn' || t.type === 'apex') {
      if (!FQDN_PATTERN.test(v)) errors.push(`${prefix}: value "${v}" is not a valid FQDN`);
    } else if (t.type === 'ip') {
      if (!isValidIp(v)) errors.push(`${prefix}: value "${v}" is not a valid IPv4 address`);
    } else if (t.type === 'cidr') {
      if (!isValidCidr(v)) errors.push(`${prefix}: value "${v}" is not a valid CIDR`);
    }
  }
  if (t.owner && (typeof t.owner !== 'string' || t.owner.length > 64)) {
    errors.push(`${prefix}: owner must be a string ≤64 chars`);
  }
  if (t.tags && !Array.isArray(t.tags)) {
    errors.push(`${prefix}: tags must be an array of strings`);
  }
  if (Array.isArray(t.tags)) {
    for (const tag of t.tags) {
      if (!SLUG_TAG.test(tag)) errors.push(`${prefix}: tag "${tag}" must be alphanum/hyphen, ≤30 chars`);
    }
  }
  if (t.notes && (typeof t.notes !== 'string' || t.notes.length > 500)) {
    errors.push(`${prefix}: notes must be ≤500 chars`);
  }
  return errors;
}

// ─── GitHub API helpers ──────────────────────────────────────────
async function ghRequest(path, init = {}) {
  const res = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'commandsentry-asm-bulk-add',
      ...(init.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${res.status}: ${text.slice(0, 400)}`);
  }
  return res.json();
}

async function getTargetsFile(repo, branch) {
  return ghRequest(`/repos/${repo}/contents/data/targets.yml?ref=${encodeURIComponent(branch)}`);
}

async function commitTargetsFile(repo, branch, content, sha, message) {
  return ghRequest(`/repos/${repo}/contents/data/targets.yml`, {
    method: 'PUT',
    body: JSON.stringify({
      message,
      content: Buffer.from(content, 'utf8').toString('base64'),
      sha,
      branch,
      committer: {
        name:  'commandsentry-bot',
        email: 'commandsentry-bot@users.noreply.github.com',
      },
    }),
  });
}

// ─── Main handler ────────────────────────────────────────────────
exports.handler = async (event) => {
  const json = (status, payload) => ({
    statusCode: status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    body: JSON.stringify(payload),
  });

  if (event.httpMethod !== 'POST') {
    return json(405, { ok: false, error: 'Method Not Allowed — POST only' });
  }

  const repo   = process.env.GITHUB_REPO;
  const token  = process.env.GITHUB_TOKEN;
  const branch = process.env.GITHUB_BRANCH || 'main';
  if (!repo || !token) {
    return json(500, { ok: false, error: 'server config missing: GITHUB_REPO or GITHUB_TOKEN env var not set' });
  }

  // Parse body
  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json(400, { ok: false, error: 'request body is not valid JSON' });
  }

  // Single batch-level attestation covers all targets in the request
  if (body.attest !== true) {
    return json(400, { ok: false, error: 'attest must be true — you must attest authorization to scan all targets in this batch' });
  }
  if (!Array.isArray(body.targets) || body.targets.length === 0) {
    return json(400, { ok: false, error: 'targets must be a non-empty array' });
  }
  if (body.targets.length > MAX_BATCH) {
    return json(400, { ok: false, error: `batch too large — max ${MAX_BATCH} targets per request, got ${body.targets.length}` });
  }

  // Validate every target. All-or-nothing — one bad row rejects the batch
  // (so a partially-applied batch can't leave the YAML in a half-state).
  const validationErrors = [];
  body.targets.forEach((t, i) => {
    validationErrors.push(...validateTarget(t, i));
  });
  if (validationErrors.length) {
    return json(400, { ok: false, error: 'validation failed', details: validationErrors });
  }

  // Reject in-batch ID collisions (duplicate IDs within the request itself)
  const seen = new Set();
  for (const t of body.targets) {
    if (seen.has(t.id)) {
      return json(400, { ok: false, error: `duplicate id "${t.id}" within batch` });
    }
    seen.add(t.id);
  }

  // Normalize each target to the YAML shape
  const newTargets = body.targets.map(t => ({
    id:             t.id,
    type:           t.type,
    value:          t.value.trim().toLowerCase(),
    scope_verified: true,
    owner:          (t.owner || 'unknown').trim(),
    tags:           Array.isArray(t.tags) ? t.tags : [],
    notes:          (t.notes || '').trim(),
  }));

  try {
    // 1. Fetch current targets.yml
    const file = await getTargetsFile(repo, branch);
    const text = Buffer.from(file.content, file.encoding || 'base64').toString('utf8');
    const doc  = yaml.load(text) || {};
    if (!Array.isArray(doc.targets)) doc.targets = [];

    // 2. Filter out targets whose ID already exists in the file (skip, don't fail)
    const existingIds = new Set(doc.targets.filter(Boolean).map(t => t.id));
    const skipped = [];
    const toAdd   = [];
    for (const t of newTargets) {
      if (existingIds.has(t.id)) {
        skipped.push({ id: t.id, reason: 'already exists' });
      } else {
        toAdd.push(t);
      }
    }

    if (toAdd.length === 0) {
      return json(409, {
        ok: false,
        error: 'all targets in batch already exist',
        skipped,
      });
    }

    // 3. Append all new targets
    doc.targets.push(...toAdd);

    // 4. Re-serialize
    const newText = yaml.dump(doc, { lineWidth: -1, sortKeys: false, noRefs: true });

    // 5. Single commit. Body lists the IDs for the diff-aware workflow to pick up.
    //    Header line stays in "add-target via dashboard:" format so the diff-trigger
    //    pattern matcher recognizes it.
    const idList = toAdd.map(t => t.id).join(', ');
    const summary = toAdd.length === 1
      ? `add-target via dashboard: ${toAdd[0].id} (${toAdd[0].type}: ${toAdd[0].value})`
      : `add-target via dashboard: bulk +${toAdd.length} targets`;
    const detail = toAdd.map(t => `  - ${t.id} (${t.type}: ${t.value})`).join('\n');
    const commitMsg = `${summary}\n\nIDs:\n${detail}`;
    const result = await commitTargetsFile(repo, branch, newText, file.sha, commitMsg);

    return json(200, {
      ok:           true,
      added_count:  toAdd.length,
      target_ids:   toAdd.map(t => t.id),
      skipped,
      commit: {
        sha: result.commit?.sha,
        url: result.commit?.html_url,
      },
      next: 'GitHub Actions will scan all newly-added IDs in a single diff-aware run.',
    });
  } catch (e) {
    return json(502, { ok: false, error: 'GitHub commit failed', detail: e.message });
  }
};
