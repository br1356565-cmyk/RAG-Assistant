#!/usr/bin/env bash
# Creates four PRIVATE demo repos under your GitHub account with deliberately outdated
# dependencies, so Dependabot raises real alerts for the demo:
#   demo-shop-web     (topic team-web)       npm: lodash, axios, minimist
#   demo-etl-jobs     (topic team-data)      pip: PyYAML, requests, urllib3
#   demo-infra-terraform (name -> platform)  pip tooling: Jinja2, urllib3
#   demo-scratch      (no topic)             lands in the admin's unowned queue
#
# Nothing here runs: the repos only contain manifests and a README. No workflows.
# Requires: gh (logged in), git. Optional: npm (adds a lockfile for more precise alerts).
# Remove later with: gh repo delete <owner>/<name> --yes   (needs the delete_repo scope)
set -euo pipefail

command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Run: gh auth login (or set GH_TOKEN)"; exit 1; }
gh auth setup-git >/dev/null 2>&1 || true   # lets `git push` use the same credentials (needed in Actions)
OWNER=$(gh api user --jq .login)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
echo "Creating demo repos under $OWNER (private)"

make_repo() {   # name topic description
  local name=$1 topic=$2 desc=$3 dir="$WORK/$1"
  if gh repo view "$OWNER/$name" >/dev/null 2>&1; then
    echo "  $name exists, skipping"; return
  fi
  git -C "$dir" init -q -b main
  git -C "$dir" add -A
  git -C "$dir" -c user.name="demo" -c user.email="demo@users.noreply.github.com" commit -qm "Demo manifests (intentionally outdated)"
  gh repo create "$OWNER/$name" --private --description "$desc" --source "$dir" --push >/dev/null
  [ -n "$topic" ] && gh repo edit "$OWNER/$name" --add-topic "$topic" >/dev/null
  # Turn on Dependabot alerts (this also enables the dependency graph).
  gh api -X PUT "repos/$OWNER/$name/vulnerability-alerts" >/dev/null
  echo "  created $name${topic:+ (topic $topic)}"
}

readme() { printf '# %s\n\nDemo repo for the DevOps audit assistant. Dependencies are intentionally outdated. Nothing here is deployed.\n' "$1" > "$2/README.md"; }

# web: npm
d="$WORK/demo-shop-web"; mkdir -p "$d"; readme demo-shop-web "$d"
cat > "$d/package.json" <<'JSON'
{
  "name": "demo-shop-web",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "axios": "0.21.0",
    "lodash": "4.17.15",
    "minimist": "1.2.5"
  }
}
JSON
if command -v npm >/dev/null; then (cd "$d" && npm install --package-lock-only --ignore-scripts --silent >/dev/null 2>&1) || true; fi
make_repo demo-shop-web team-web "Demo: web team storefront"

# data: python
d="$WORK/demo-etl-jobs"; mkdir -p "$d"; readme demo-etl-jobs "$d"
printf 'PyYAML==5.3\nrequests==2.19.1\nurllib3==1.24.1\n' > "$d/requirements.txt"
make_repo demo-etl-jobs team-data "Demo: data team ETL jobs"

# platform: matched by name (contains "infra")
d="$WORK/demo-infra-terraform"; mkdir -p "$d/tools"; readme demo-infra-terraform "$d"
printf 'terraform {\n  required_version = ">= 1.6"\n}\n' > "$d/main.tf"
printf 'Jinja2==2.10.1\nurllib3==1.24.1\n' > "$d/tools/requirements.txt"
make_repo demo-infra-terraform "" "Demo: platform Terraform"

# unowned
d="$WORK/demo-scratch"; mkdir -p "$d"; readme demo-scratch "$d"
printf 'requests==2.19.1\n' > "$d/requirements.txt"
make_repo demo-scratch "" "Demo: repo with no owner"

echo
echo "Done. Dependabot usually raises alerts within a few minutes:"
echo "  https://github.com/$OWNER/demo-shop-web/security/dependabot"
echo "Install your GitHub App on these four repos (or on all repos)."
