/**
 * COMMANDsentry — scan-status Netlify Function
 * ─────────────────────────────────────────────
 * Queries GitHub Actions API for the current state of asm-discover workflow runs.
 * Used by the dashboard to show live scan status without exposing GH tokens to the browser.
 *
 * Endpoints:
 *   GET /api/scan-status                   — latest run, any target
 *   GET /api/scan-status?target_id=X       — most recent run that mentions target X
 *                                            (matches by commit message containing the ID)
 *   GET /api/scan-status?run_id=N          — specific run
 *
 * Returns JSON:
 *   {
 *     ok: true,
 *     run_id, run_url, html_url,
 *     status,        // queued | in_progress | completed
 *     conclusion,    // success | failure | cancelled | null (when in progress)
 *     mode,          // single | all | diff | skipped (from workflow output)
 *     created_at, started_at, updated_at, completed_at,
 *     elapsed_seconds,
 *     event,         // push | workflow_dispatch | schedule
 *     commit_message,
 *     job: {
 *       status, conclusion,
 *       current_step,           // step name currently in_progress (or last completed)
 *       total_steps,
 *       completed_steps,
 *       progress_pct,           // 0–100
 *       step_timeline: [
 *         { name, status, conclusion, started_at, completed_at }
 *       ]
 *     }
 *   }
 *
 * Auth model: Netlify site password protection guards this endpoint
 * (same as /api/add-target). Function uses GITHUB_TOKEN env var to talk to GH.
 */

const REPO = process.env.GITHUB_REPO || "bklynhowster/commandsentry-asm";
const TOKEN = process.env.GITHUB_TOKEN || "";
const WORKFLOW_FILE = "asm-discover.yml";

async function gh(path) {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "commandsentry-asm-scan-status/1.0",
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${res.status}: ${text.slice(0, 300)}`);
  }
  return res.json();
}

function buildJobSummary(jobsResp) {
  const job = (jobsResp.jobs || [])[0];
  if (!job) return null;
  const steps = job.steps || [];
  // Don't count internal "Set up job" / "Complete job" / Post-* steps for user UX
  const userSteps = steps.filter((s) => {
    const n = (s.name || "").toLowerCase();
    return !n.startsWith("set up job") && !n.startsWith("complete job") && !n.startsWith("post ");
  });
  const total = userSteps.length;
  const completed = userSteps.filter((s) => s.status === "completed").length;
  const inProgress = userSteps.find((s) => s.status === "in_progress");
  const current = inProgress
    ? inProgress.name
    : userSteps.filter((s) => s.status === "completed").slice(-1)[0]?.name || null;

  return {
    status:     job.status,
    conclusion: job.conclusion,
    current_step:    current,
    total_steps:     total,
    completed_steps: completed,
    progress_pct:    total ? Math.round((completed / total) * 100) : 0,
    step_timeline:   userSteps.map((s) => ({
      name:         s.name,
      status:       s.status,
      conclusion:   s.conclusion,
      started_at:   s.started_at,
      completed_at: s.completed_at,
    })),
  };
}

async function findRunForTarget(targetId) {
  const data = await gh(`/repos/${REPO}/actions/workflows/${WORKFLOW_FILE}/runs?per_page=20`);
  const runs = data.workflow_runs || [];
  // Match: commit message contains the target ID (form-add commits look like
  // "add-target via dashboard: <id> (...)"; manual dispatch input is in display_title)
  return runs.find((r) => {
    const hay = `${r.display_title || ""} ${r.head_commit?.message || ""}`.toLowerCase();
    return hay.includes(targetId.toLowerCase());
  }) || runs[0];
}

async function latestRun() {
  const data = await gh(`/repos/${REPO}/actions/workflows/${WORKFLOW_FILE}/runs?per_page=1`);
  return (data.workflow_runs || [])[0];
}

async function getRunById(runId) {
  return gh(`/repos/${REPO}/actions/runs/${runId}`);
}

function elapsedSeconds(run) {
  const start = run.run_started_at || run.created_at;
  if (!start) return 0;
  const end = run.updated_at || new Date().toISOString();
  return Math.max(0, Math.floor((new Date(end) - new Date(start)) / 1000));
}

exports.handler = async (event) => {
  const json = (status, payload) => ({
    statusCode: status,
    headers: {
      "Content-Type":  "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(payload),
  });

  if (event.httpMethod !== "GET") {
    return json(405, { ok: false, error: "GET only" });
  }
  if (!TOKEN) {
    return json(500, { ok: false, error: "server config: GITHUB_TOKEN not set" });
  }

  const params = event.queryStringParameters || {};
  const runId = params.run_id;
  const targetId = params.target_id;

  try {
    let run = null;
    if (runId)        run = await getRunById(runId);
    else if (targetId) run = await findRunForTarget(targetId);
    else               run = await latestRun();

    if (!run) {
      return json(404, { ok: false, error: "no runs found" });
    }

    // Get jobs for the run (always 1 job, "discover")
    const jobsResp = await gh(`/repos/${REPO}/actions/runs/${run.id}/jobs`);
    const jobSummary = buildJobSummary(jobsResp);

    // Try to extract mode from job output (if the run has completed and we got a step summary)
    // We don't have a clean way to read step outputs via API, so we infer mode from commit
    // message patterns. asm-scan: commits indicate scan happened; everything else is skip.
    let mode = null;
    const cm = (run.head_commit?.message || "").toLowerCase();
    if (cm.startsWith("asm-scan:")) mode = "scan";
    else if (cm.startsWith("add-target via dashboard:")) mode = (run.event === "workflow_dispatch" ? "single" : "diff");
    else if (run.event === "schedule") mode = "all";

    return json(200, {
      ok: true,
      run_id:        run.id,
      run_url:       run.url,
      html_url:      run.html_url,
      status:        run.status,
      conclusion:    run.conclusion,
      mode,
      created_at:    run.created_at,
      started_at:    run.run_started_at,
      updated_at:    run.updated_at,
      completed_at:  (run.status === "completed") ? run.updated_at : null,
      elapsed_seconds: elapsedSeconds(run),
      event:         run.event,
      commit_sha:    run.head_sha,
      commit_message: run.head_commit?.message?.split("\n")[0] || run.display_title,
      job: jobSummary,
    });
  } catch (e) {
    return json(502, { ok: false, error: "GitHub API failure", detail: e.message });
  }
};
