#!/usr/bin/env bash
# COMMANDsentry — one-shot repo bootstrap
# ────────────────────────────────────────
# Initializes git, creates a private GitHub repo via `gh`, pushes everything.
# Assumes:
#   - You are inside the COMMANDsentry folder
#   - `gh` CLI is installed and authenticated (`gh auth status` works)
#   - You're OK with the repo being created under your default GitHub account
#
# Usage:
#   ./bootstrap.sh                          # default: commandsentry-asm
#   ./bootstrap.sh my-other-repo-name       # custom repo name

set -uo pipefail

REPO_NAME="${1:-commandsentry-asm}"
REPO_DESC="COMMANDsentry — self-hosted Attack Surface Management"
DEFAULT_BRANCH="main"

cd "$(dirname "$0")"

echo "═══ COMMANDsentry bootstrap ═══"
echo "Repo name:    $REPO_NAME"
echo "Visibility:   private"
echo "Branch:       $DEFAULT_BRANCH"
echo ""

# ─── Sanity: gh CLI ─────────────────────────────────────
if ! command -v gh &>/dev/null; then
  echo "ERROR: 'gh' CLI not installed. Install with: brew install gh"
  echo "Then run: gh auth login"
  exit 1
fi

if ! gh auth status &>/dev/null; then
  echo "ERROR: 'gh' not authenticated. Run: gh auth login"
  exit 1
fi

GH_USER=$(gh api user --jq .login)
echo "Authenticated as: $GH_USER"
echo ""

# ─── Sanity: not already a repo ────────────────────────
if [[ -d ".git" ]]; then
  echo "WARN: .git already exists in this folder. Skipping git init."
else
  git init -b "$DEFAULT_BRANCH" >/dev/null
fi

# ─── First commit (if needed) ──────────────────────────
git config user.name  "${GH_USER}" 2>/dev/null || true
git config user.email "${GH_USER}@users.noreply.github.com" 2>/dev/null || true

git add .
if ! git diff --staged --quiet 2>/dev/null; then
  git commit -m "Initial commit — COMMANDsentry scaffold + scanner + dashboard" >/dev/null
  echo "Created initial commit."
else
  echo "Nothing new to commit."
fi

# ─── Create remote ─────────────────────────────────────
if gh repo view "${GH_USER}/${REPO_NAME}" &>/dev/null; then
  echo "Repo ${GH_USER}/${REPO_NAME} already exists."
  REMOTE_URL=$(gh repo view "${GH_USER}/${REPO_NAME}" --json sshUrl --jq .sshUrl)
else
  echo "Creating private repo ${GH_USER}/${REPO_NAME}…"
  gh repo create "$REPO_NAME" \
    --private \
    --description "$REPO_DESC" \
    --source . \
    --remote origin \
    --push
  echo "Repo created + pushed."
  exit 0
fi

# Repo existed already — wire remote and push
if ! git remote get-url origin &>/dev/null; then
  git remote add origin "$REMOTE_URL"
fi
git push -u origin "$DEFAULT_BRANCH"

echo ""
echo "═══ Done ═══"
echo "Repo URL:  https://github.com/${GH_USER}/${REPO_NAME}"
echo ""
echo "Next:"
echo "  1. Visit the repo → Actions tab."
echo "  2. Verify the 'ASM Discover' workflow appears."
echo "  3. Click 'Run workflow' to kick off a manual scan, OR wait for the next 6h cron tick."
