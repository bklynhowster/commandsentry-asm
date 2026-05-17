# COMMANDsentry alerter

Daily posture digest. Queries the canonical Postgres data layer for status
transitions since the last successful run, renders an HTML + plaintext email,
sends it via Resend. Schedule lives in `.github/workflows/alerter.yml`.

## What it watches

| Trigger | Source |
|---|---|
| Finding flipped to `confirmed` / `open` (passed 2-scan confirmation) | `v_alerter_changes` |
| Finding flipped to `regressed` (was fixed, came back) | `v_alerter_changes` |
| Asset elevated to CRITICAL / HIGH / MODERATE-HIGH | `v_alerter_high_risk_assets` |
| "All clear" heartbeat when nothing changed | always (so silence ≠ broken alerter) |

## One-time setup

### 1. Apply the SQL migration

```bash
psql "$SUPABASE_DSN" -f scripts/db/alerter.sql
```

Creates `meta_alerter_runs`, `v_alerter_changes`, `v_alerter_high_risk_assets`,
and the `alerter_last_window_end()` helper.

### 2. Sign up for Resend + verify a sending domain

1. Create account at https://resend.com
2. Settings → Domains → Add domain → `goldenlaneinc.com`
3. Add the DNS records Resend gives you (SPF + DKIM TXT records) at your
   registrar. Records propagate in ~minutes; click "Verify" until green.
4. Settings → API Keys → Create. Copy the `re_…` token.

(If you want to skip the domain step for a quick test, use Resend's sandbox
`onboarding@resend.dev` as the `from` — it'll land in spam more often but
works without DNS changes.)

### 3. Add GitHub Secrets

Repo → Settings → Secrets and variables → Actions:

| Name | Value |
|---|---|
| `SUPABASE_DSN` | session pooler URL with password (NOT the direct IPv6 one) |
| `RESEND_API_KEY` | the `re_…` token from step 2 |

Optional vars (override defaults via repo variables, not secrets):

| Name | Default |
|---|---|
| `ALERTER_FROM` | `commandsentry@goldenlaneinc.com` |
| `ALERTER_TO` | `hschneider@commandcompanies.com,howiehow@mac.com` |
| `ALERTER_DASHBOARD_URL` | Supabase project dashboard link |

### 4. Smoke-test with dry-run

From the Actions tab:
1. Pick "Daily posture digest"
2. Click "Run workflow"
3. Set the `dry_run` input to `true`
4. Watch the log — should print "DRY RUN — would send to:" plus the body

If that's clean, run again with `dry_run=false` to send a real email.

## Local testing

```bash
export SUPABASE_DSN='postgresql://postgres.PROJ:PASS@aws-1-us-east-1.pooler.supabase.com:5432/postgres'
export RESEND_API_KEY='re_…'

# Render only — no Resend call, no DB write:
python3 scripts/alerter/run_alerter.py --dry-run

# Real send:
python3 scripts/alerter/run_alerter.py
```

## State tracking

Every run writes a row to `meta_alerter_runs`:

```sql
SELECT id, started_at, finished_at, window_start, window_end,
       new_confirmed, new_regressed, new_high_risk,
       email_sent, status, error_message
FROM meta_alerter_runs
ORDER BY id DESC
LIMIT 10;
```

The next run uses `MAX(window_end) WHERE status = 'success'` as its
`window_start`, so failed runs don't drop notifications — the next
successful run picks them up.

## Schedule

`.github/workflows/alerter.yml` runs at `0 12 * * *` UTC (07:00 ET / 08:00
EDT). Edit the cron line to change the time. Multiple invocations a day are
safe — each one only catches transitions since the last successful run.
