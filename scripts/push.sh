#!/usr/bin/env bash
# push.sh — rebase-then-push helper for COMMANDsentry.
#
# Why: GitHub Actions commits asset JSON updates after every scheduled scan
# (web/data/*.json), so the remote is almost always ahead of your local
# main by the time you go to push. A bare `git push` fails with
# "Updates were rejected because the remote contains work you do not
# have locally." This helper pulls (rebased, since pull.rebase=true is
# set in the local .git/config) and then pushes in one shot.
#
# Usage:
#   ./scripts/push.sh
#   ./scripts/push.sh main          # explicit branch
#
# If the rebase finds a conflict (rare — would only happen if you edited a
# web/data/*.json file the scanner also touched), git will pause and you
# can resolve manually.

set -e

cd "$(git rev-parse --show-toplevel)"

BRANCH="${1:-main}"

echo ">> Fetching + rebasing onto origin/$BRANCH..."
git pull --rebase --autostash origin "$BRANCH"

echo ">> Pushing $BRANCH..."
git push origin "$BRANCH"

echo ">> Done."
