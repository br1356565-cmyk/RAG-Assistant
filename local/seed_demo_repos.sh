#!/usr/bin/env bash
# Creates (or updates) four PRIVATE demo repos under your GitHub account from
# local/demo-repos/<name>/. They are deliberately vulnerable so every agent path has
# something real to work on; local/demo-repos/SCENARIOS.md says what each one exercises.
#
#   demo-shop-web         topic team-web    Node/Express: axios, lodash (reachable), minimist (dev, transitive)
#   demo-etl-jobs         topic team-data   Python: PyYAML, requests (reachable), urllib3 (indirect)
#   demo-infra-terraform  name -> platform  Python Jinja2 on trusted templates; a Go module
#   demo-scratch          no owner          lands in the admin's unowned queue
#
# Existing repos are updated in place (one new commit), so re-running is safe.
# Nothing in these repos runs anywhere: no workflows, nothing deployed.
# Requires: gh (logged in), git. Optional: npm (lockfile), go (go.sum); both exist on GitHub runners.
# Remove later with: gh repo delete <owner>/<name> --yes   (needs the delete_repo scope)
set -euo pipefail

command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Run: gh auth login (or set GH_TOKEN)"; exit 1; }
gh auth setup-git >/dev/null 2>&1 || true   # lets git push use the same credentials (needed in Actions)
SRC="$(cd "$(dirname "$0")" && pwd)/demo-repos"
OWNER=$(gh api user --jq .login)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
GIT=(git -c user.name="demo" -c user.email="demo@users.noreply.github.com")
echo "Seeding demo repos under $OWNER (private)"

prepare() {   # name -> builds the tree in $WORK/<name>/tree
  local name=$1 tree="$WORK/$1/tree"
  mkdir -p "$tree" && cp -R "$SRC/$name/." "$tree/"
  if [ -f "$tree/package.json" ] && [ ! -f "$tree/package-lock.json" ] && command -v npm >/dev/null; then
    (cd "$tree" && npm install --package-lock-only --ignore-scripts --silent >/dev/null 2>&1) || echo "  (npm lockfile skipped)"
  fi
  while IFS= read -r mod; do
    (cd "$(dirname "$mod")" && command -v go >/dev/null && GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1) || true
  done < <(find "$tree" -name go.mod)
}

publish() {   # name topic description
  local name=$1 topic=$2 desc=$3 tree="$WORK/$1/tree"
  prepare "$name"
  if gh repo view "$OWNER/$name" >/dev/null 2>&1; then
    gh repo clone "$OWNER/$name" "$WORK/$name/repo" -- -q
    find "$WORK/$name/repo" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
    cp -R "$tree/." "$WORK/$name/repo/"
    "${GIT[@]}" -C "$WORK/$name/repo" add -A
    if "${GIT[@]}" -C "$WORK/$name/repo" diff --cached --quiet; then
      echo "  $name unchanged"
    else
      "${GIT[@]}" -C "$WORK/$name/repo" commit -qm "Demo content: realistic vulnerable code and manifests"
      "${GIT[@]}" -C "$WORK/$name/repo" push -q
      echo "  updated $name"
    fi
  else
    "${GIT[@]}" -C "$tree" init -q -b main
    "${GIT[@]}" -C "$tree" add -A
    "${GIT[@]}" -C "$tree" commit -qm "Demo content: realistic vulnerable code and manifests"
    gh repo create "$OWNER/$name" --private --description "$desc" --source "$tree" --push >/dev/null
    echo "  created $name"
  fi
  [ -n "$topic" ] && gh repo edit "$OWNER/$name" --add-topic "$topic" >/dev/null
  # Dependabot alerts on (this also turns on the dependency graph).
  gh api -X PUT "repos/$OWNER/$name/vulnerability-alerts" >/dev/null
}

publish demo-shop-web        team-web  "Demo: web team storefront API (deliberately vulnerable)"
publish demo-etl-jobs        team-data "Demo: data team ETL jobs (deliberately vulnerable)"
publish demo-infra-terraform ""        "Demo: platform Terraform and tooling"
publish demo-scratch         ""        "Demo: repo with no owner"

echo
echo "Done. Dependabot raises alerts within a few minutes:"
echo "  https://github.com/$OWNER/demo-shop-web/security/dependabot"
echo "Make sure your GitHub App (and the fix-bot App, if you made one) can access these repos,"
echo "then start a collection run. Scenarios to try: local/demo-repos/SCENARIOS.md"
