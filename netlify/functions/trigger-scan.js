/**
 * COMMANDsentry — trigger-scan Netlify Function
 * ──────────────────────────────────────────────
 * Triggers an asm-discover workflow_dispatch via GitHub API so a user can
 * re-scan a specific target (or all targets) without leaving the dashboard.
 *
 * Body: { target?: string }
 *   - omit or "all" → scan-all mode
 *   - "<target-id>"  → single-target mode (matches the workflow's `target` input)
 *
 * Returns: { ok: true, target, run_url } or error.
 *
 * Per-target cooldown: prevents accidental queue-spam from rapid clicks.
 * Default 60 seconds between triggers for the same target. Cooldown is enforced
 * by checking the most recent run for that target via the GitHub API. Use
 * ?force=1 in the body to bypass (e.g. for diagnostic scenarios).
 *
 * Auth model: same Netlify password gate as the other Functions.
 * Env vars: GITHUB_TOKEN, GITHUB_REPO, GITHUB_BRANCH (defaults to "main").
 */

const REPO   = process.env.GITHUB_REPO   || "bklynhowster/commandsentry-asm";
const TOKEN  = process.env.GITHUB_TOKEN  || "";
const BRANCH = process.env.GITHUB_BRANCH || "main";
const WORKFLOW_FILE = "asm-discover.yml";

const COOLDOWN_SECONDS = 60;

async function gh(path, init = {}) {
  const res = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "commandsentry-asm-trigger-scan/1.0",
      ...(init.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${res.status}: ${text.slice(0, 400)}`);
  }
  // workflow_dispatch returns 204 No Content — no JSON body
  if (res.status === 204) return null;
  return res.json();
}

// Find the most recent run for a given target (or any run if target=all)
// to enforce the cooldown.
async function mostRecentRunFor(target) {
  const data = await gh(`/repos/${REPO}/actions/workflows/${WORKFLOW_FILE}/runs?per_page=20`);
  const runs = data.workflow_runs || [];
  // Match by display_title (which contains the target input) or by commit message.
  return runs.find((r) => {
    const hay = `${r.display_title || ""} ${r.head_commit?.message || ""}`.toLowerCase();
    return hay.includes((target || "").toLowerCase());
  }) || runs[0];
}

exports.handler = async (event) => {
  const json = (status, payload) => ({
    statusCode: status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify(payload),
  });

  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "POST only" });
  }
  if (!TOKEN) {
    return json(500, { ok: false, error: "server config: GITHUB_TOKEN not set" });
  }

  let body = {};
  try { body = JSON.parse(event.body || "{}"); }
  catch { return json(400, { ok: false, error: "request body is not valid JSON" }); }

  const target = (body.target && String(body.target).trim()) || "all";
  const force  = body.force === true || body.force === "1";

  // Validate target ID format (mirror the targets.yml ID validation)
  if (target !== "all" && !/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(target)) {
    return json(400, { ok: false, error: `invalid target id "${target}"` });
  }

  try {
    // Cooldown check — protect against rapid-fire clicks
    if (!force) {
      const recent = await mostRecentRunFor(target);
      if (recent) {
        const createdAt = new Date(recent.created_at).getTime();
        const ageSec = (Date.now() - createdAt) / 1000;
        const inProgress = recent.status === "queued" || recent.status === "in_progress";
        if (inProgress) {
          return json(409, {
            ok: false,
            error: `a scan is already running for "${target}" (started ${Math.floor(ageSec)}s ago)`,
            run_url: recent.html_url,
            current_status: recent.status,
          });
        }
        if (ageSec < COOLDOWN_SECONDS) {
          return json(429, {
            ok: false,
            error: `cooldown — wait ${Math.ceil(COOLDOWN_SECONDS - ageSec)}s before re-triggering "${target}" (last run finished ${Math.floor(ageSec)}s ago)`,
            cooldown_remaining_seconds: Math.ceil(COOLDOWN_SECONDS - ageSec),
          });
        }
      }
    }

    // Fire workflow_dispatch with the target input
    await gh(`/repos/${REPO}/actions/workflows/${WORKFLOW_FILE}/dispatches`, {
      method: "POST",
      body: JSON.stringify({
        ref: BRANCH,
        inputs: { target },
      }),
    });

    return json(200, {
      ok: true,
      target,
      mode: target === "all" ? "all" : "single",
      next: `Workflow queued. Watch the live scan banner at the top of the dashboard, or run #N at https://github.com/${REPO}/actions/workflows/${WORKFLOW_FILE}`,
    });
  } catch (e) {
    return json(502, { ok: false, error: "GitHub API failure", detail: e.message });
  }
};
