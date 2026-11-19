#!/usr/bin/env bash
# One-time hardening of the GitHub repository settings (run once by the owner, `gh` authenticated as
# an admin of the repository). Idempotent: re-running updates the same rulesets.
#
# Usage: scripts/protect-repo.sh [--repo OWNER/NAME] [--dry-run]
#
# What it sets (see docs/SECURITY-SUPPLY-CHAIN.md):
#   * ruleset "main": no deletion, no force-push, changes only through a pull request whose required
#     checks passed (Rust, Python, macOS, repository hygiene, cargo-deny); admins may only bypass via
#     a pull request (never a direct push);
#   * ruleset "release tags": only admins can create, move or delete `v*` tags (a tag triggers the
#     signed release workflow);
#   * Actions: default GITHUB_TOKEN read-only, workflows cannot approve pull requests, every
#     workflow run from a fork needs approval;
#   * security: Dependabot alerts + security updates, secret scanning + push protection.
set -euo pipefail

repo="WLDEUS/Parabellum"
dry=0
while (($# > 0)); do
    case "$1" in
        --repo)
            repo="${2:?--repo needs OWNER/NAME}"
            shift
            ;;
        --dry-run) dry=1 ;;
        -h | --help)
            sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "erreur : option inconnue : $1" >&2
            exit 2
            ;;
    esac
    shift
done

command -v gh >/dev/null 2>&1 || { echo "gh introuvable : brew install gh && gh auth login" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh non authentifié : gh auth login" >&2; exit 1; }

api() {
    local method="$1" path="$2" body="${3:-}"
    if ((dry)); then
        echo "DRY $method $path ${body:0:200}"
        return 0
    fi
    if [[ -n "$body" ]]; then
        gh api --method "$method" -H "Accept: application/vnd.github+json" "$path" --input - <<<"$body" >/dev/null
    else
        gh api --method "$method" -H "Accept: application/vnd.github+json" "$path" >/dev/null
    fi
}

# Create or update a ruleset by name.
upsert_ruleset() {
    local name="$1" body="$2" id
    id="$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id" 2>/dev/null | head -n1 || true)"
    if [[ -n "$id" ]]; then
        api PUT "repos/$repo/rulesets/$id" "$body"
        echo "==> ruleset « $name » mis à jour"
    else
        api POST "repos/$repo/rulesets" "$body"
        echo "==> ruleset « $name » créé"
    fi
}

# RepositoryRole 5 = admin.
upsert_ruleset "main" '{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" } ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "Rust (Linux)" },
          { "context": "Python (pipeline + ml)" },
          { "context": "macOS arm64 build + pkg" },
          { "context": "Repository hygiene" },
          { "context": "Rust dependencies (cargo-deny)" }
        ] } }
  ]
}'

upsert_ruleset "release tags" '{
  "name": "release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" } ],
  "rules": [ { "type": "creation" }, { "type": "update" }, { "type": "deletion" } ]
}'

api PUT "repos/$repo/actions/permissions/workflow" \
    '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'
echo "==> Actions : jeton par défaut en lecture seule, pas d'approbation de PR par les workflows"
api PUT "repos/$repo/actions/permissions/fork-pr-contributor-approval" '{"approval_policy":"all_external_contributors"}' ||
    echo "attention : approbation des PR de forks non réglée (réglage indisponible ?)" >&2
api PUT "repos/$repo/vulnerability-alerts"
api PUT "repos/$repo/automated-security-fixes"
echo "==> Dependabot : alertes + correctifs de sécurité"
api PATCH "repos/$repo" \
    '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}' ||
    echo "attention : secret scanning non activé (dépôt privé sans GitHub Advanced Security ?)" >&2
echo "==> secret scanning + protection au push"
echo "Terminé. Vérifie : https://github.com/$repo/settings/rules"
