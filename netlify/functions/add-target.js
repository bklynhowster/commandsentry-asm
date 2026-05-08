/**
 * COMMANDsentry — add-target Netlify Function
 * ────────────────────────────────────────────
 * Receives a new target from the dashboard form, validates it, appends it
 * to data/targets.yml in the GitHub repo, and commits. The push triggers
 * the asm-discover workflow which scans the new target.
 *
 * Auth model: Netlify site password protection is the visitor gate.
 *             Any request reaching this function has already passed it.
 *
 * Env vars required (set in Netlify project Configuration → Environment):
 *   GITHUB_TOKEN  — Personal Access Token with `repo` scope on commandsentry-asm
 *   GITHUB_REPO   — e.g. "bklynhowster/commandsentry-asm"
 *   GITHUB_BRANCH — optional, defaults to "main"
 */

const yaml = require('js-yaml');

// ─── Validation rules ────────────────────────────────────────────
const TARGET_TYPES = ['fqdn', 'apex', 'ip', 'cidr'];

const ID_PATTERN     = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
const FQDN_PATTERN   = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
const IPV4_PATTERN   = /^(\d{1,3}\.){3}\d{1,3}$/;
const CIDR_PATTERN   = /^(\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[1-2]\d|3[0-2])$/;
const SLUG_TAG       = /^[a-z0-9][a-z0-9-]{0,30}$/i;

function isValidIp(s) {
  if (!IPV4_PATTERN.test(s)) return false;
  return s.split('.').every(o => Number(o) >= 0 && Number(o) <= 255);
}

function isValidCidr(s) {
  if (!CIDR_PATTERN.test(s)) return false;
  const [ip] = s.split('/');
  return isValidIp(ip);
}

function validate(body) {
  const errors = [];

  if (!body || typeof body !== 'object') {
    return ['request body must be JSON object'];
  }

  if (!body.id || !ID_PATTERN.test(body.id)) {
    errors.push('id must be lowercase letters/digits/hyphens, 3-64 chars, no leading/trailing hyphen');
  }
  if (!TARGET_TYPES.includes(body.type)) {
    errors.push(`type must be one of: ${TARGET_TYPES.join(', ')}`);
  }
  if (!body.value || typeof body.value !== 'string') {
    errors.push('value is required');
  } else {
    const v = body.value.trim().toLowerCase();
    if (body.type === 'fqdn' || body.type === 'apex') {
      if (!FQDN_PATTERN.test(v)) errors.push(`value "${v}" is not a valid FQDN`);
    } else if (body.type === 'ip') {
      if (!isValidIp(v)) errors.push(`value "${v}" is not a valid IPv4 address`);
    } else if (body.type === 'cidr') {
      if (!isValidCidr(v)) errors.push(`value "${v}" is not a valid CIDR`);
    }
  }
  if (body.owner && (typeof body.owner !== 'string' || body.owner.length > 64)) {
    errors.push('owner must be a string ≤64 chars');
  }
  if (body.tags && !Array.isArray(body.tags)) {
    errors.push('tags must be an array of strings');
  }
  if (body.tags) {
    for (const t of body.tags) {
      if (!SLUG_TAG.test(t)) errors.push(`tag "${t}" must be alphanum/hyphen, ≤30 chars`);
    }
  }
  if (body.notes && (typeof body.notes !== 'string' || body.notes.length > 500)) {
    errors.push('notes must be ≤500 chars');
  }
  if (body.scope_verified !== true) {
    errors.push('scope_verified must be checked — you must attest authorization to scan this target');
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
      'User-Agent': 'commandsentry-asm-add-target',
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

  // Env var sanity
  const repo   = process.env.GITHUB_REPO;
  const token  = process.env.GITHUB_TOKEN;
  const branch = process.env.GITHUB_BRANCH || 'main';
  if (!repo || !token) {
    return json(500, { ok: false, error: 'server config missing: GITHUB_REPO or GITHUB_TOKEN env var not set' });
  }

  // Parse + validate
  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json(400, { ok: false, error: 'request body is not valid JSON' });
  }
  const errors = validate(body);
  if (errors.length) {
    return json(400, { ok: false, error: 'validation failed', details: errors });
  }

  // Build the target object
  const newTarget = {
    id:              body.id,
    type:            body.type,
    value:           body.value.trim().toLowerCase(),
    scope_verified:  true,
    owner:           body.owner?.trim() || 'unknown',
    tags:            Array.isArray(body.tags) ? body.tags : [],
    notes:           (body.notes || '').trim(),
  };

  try {
    // 1. Fetch current targets.yml
    const file = await getTargetsFile(repo, branch);
    const text = Buffer.from(file.content, file.encoding || 'base64').toString('utf8');
    const doc  = yaml.load(text) || {};
    if (!Array.isArray(doc.targets)) doc.targets = [];

    // 2. Reject duplicates
    if (doc.targets.find(t => t && t.id === newTarget.id)) {
      return json(409, { ok: false, error: `target id "${newTarget.id}" already exists` });
    }

    // 3. Append
    doc.targets.push(newTarget);

    // 4. Re-serialize. lineWidth: -1 prevents auto-wrapping long lines.
    const newText = yaml.dump(doc, { lineWidth: -1, sortKeys: false, noRefs: true });

    // 5. Commit
    const commitMsg = `add-target via dashboard: ${newTarget.id} (${newTarget.type}: ${newTarget.value})`;
    const result = await commitTargetsFile(repo, branch, newText, file.sha, commitMsg);

    return json(200, {
      ok: true,
      target: newTarget,
      commit: {
        sha: result.commit?.sha,
        url: result.commit?.html_url,
      },
      next: 'GitHub Actions will scan this target on the next push trigger or scheduled run. Manual trigger: gh workflow run asm-discover.yml -f target=' + newTarget.id,
    });
  } catch (e) {
    return json(502, { ok: false, error: 'GitHub commit failed', detail: e.message });
  }
};
