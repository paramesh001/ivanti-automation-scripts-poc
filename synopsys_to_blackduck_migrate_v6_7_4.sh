#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Script: synopsys_to_blackduck_migrate_v6_7_4.sh
# Purpose:
#   Audit / Dry-run / Apply / Rollback migration of Synopsys (Polaris / Coverity-on-Polaris)
#   footprints to Black Duck / Coverity-in-Polaris patterns across common CI files.
# Env inputs:
#   ROOT (default: .)     - path to cloned target repo
#   MODE (required)       - audit|dry-run|apply|rollback
#   OUT_CSV (required)    - output CSV path (absolute recommended)
#   COMMIT (default: 0)   - 1 to commit changes
#   PUSH (default: 0)     - 1 to push changes
#   REMOTE (default: origin)
#   GITHUB_TOKEN          - required if PUSH=1
#
# Notes:
#   - This script targets Azure DevOps YAML files for auto-apply/rollback,
#     but still reports other CI footprints in audit/dry-run.
#   - Edits are conservative and intended to be a mechanical starting point.
# ============================================================================

ROOT="${ROOT:-.}"
MODE="${MODE:-}"
OUT_CSV="${OUT_CSV:-}"
COMMIT="${COMMIT:-0}"
PUSH="${PUSH:-0}"
REMOTE="${REMOTE:-origin}"

TS="$(date +%Y%m%d_%H%M%S)"

# -------- Patterns (detection) --------
PAT_ADO_TASK='SynopsysSecurityScan@|BlackDuckSecurityScan@|SynopsysBridge@'
PAT_GHA_ACTION='uses:\s*synopsys-sig/synopsys-action'
PAT_BRIDGE_CLI='(^|[[:space:]/])bridge([[:space:]]|$)|--stage[[:space:]]+polaris|--stage[[:space:]]+blackduck|--input[[:space:]]+bridge\.ya?ml'
PAT_COVERITY_CLI='cov-build|cov-analyze|cov-capture|cov-commit-defects|cov-format-errors'
PAT_JENKINS_PLUGIN='withCoverityEnv|coverityScan|coverityPublisher|covBuild|covAnalyze|covCommitDefects'

PIPELINE_GLOBS=(
  ".travis.yml"
  "azure-pipelines.yml" "azure-pipelines.yaml"
  ".github/workflows/*.yml" ".github/workflows/*.yaml"
  "bamboo-specs/**/*.yml" "bamboo-specs/**/*.yaml"
  "bridge.yml" "bridge.yaml"
  "Jenkinsfile" "Jenkinsfile*"
)

# -------- Utilities --------
log(){ echo "$@" >&2; }
die(){ echo "[ERROR] $*" >&2; exit 1; }

grep_q() { # grep_q PATTERN FILE
  local pat="$1"; local f="$2"
  grep -Eq "$pat" -- "$f"
}

csv_escape() {
  # RFC4180-ish: wrap in quotes, double internal quotes, strip CR
  local s="${1//$'\r'/}"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

ensure_csv_header() {
  mkdir -p "$(dirname "$OUT_CSV")" 2>/dev/null || true
  if [[ ! -s "$OUT_CSV" ]]; then
    echo "repo,branch,build_type,package_manager_file,file_path,ci_type,found_type,invocation_style,evidence,migration_changes" >> "$OUT_CSV"
  fi
}

assert_inputs() {
  [[ -n "$MODE" ]] || die "MODE is required (audit|dry-run|apply|rollback)"
  [[ "$MODE" =~ ^(audit|dry-run|apply|rollback)$ ]] || die "Invalid MODE=$MODE"
  [[ -n "$OUT_CSV" ]] || die "OUT_CSV is required"
  [[ -d "$ROOT" ]] || die "ROOT not found: $ROOT"
  git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "ROOT is not a git repo: $ROOT"
  if [[ "$PUSH" == "1" ]]; then
    [[ -n "${GITHUB_TOKEN:-}" ]] || die "PUSH=1 requires GITHUB_TOKEN in environment"
  fi
}

repo_url_of() {
  local url
  url="$(git -C "$ROOT" config --get "remote.${REMOTE}.url" || true)"
  echo "${url:-unknown}"
}

current_branch() {
  local b
  b="$(git -C "$ROOT" branch --show-current || true)"
  echo "${b:-unknown}"
}

# Very small "build info" heuristic
build_info_of_repo() {
  local bt="unknown"
  local pm=()

  [[ -f "$ROOT/package.json" ]] && pm+=("package.json")
  [[ -f "$ROOT/pom.xml" ]] && pm+=("pom.xml")
  [[ -f "$ROOT/build.gradle" ]] && pm+=("build.gradle")
  [[ -f "$ROOT/Dockerfile" ]] && pm+=("Dockerfile")

  if [[ -f "$ROOT/package.json" ]]; then bt="npm"; fi
  if [[ -f "$ROOT/pom.xml" ]]; then bt="${bt/unknown/}maven${bt:+ +$bt}"; fi
  if [[ -f "$ROOT/build.gradle" ]]; then bt="${bt/unknown/}gradle${bt:+ +$bt}"; fi
  if [[ -f "$ROOT/Dockerfile" ]]; then bt="${bt/unknown/}docker${bt:+ +$bt}"; fi

  local pm_join="none"
  if [[ ${#pm[@]} -gt 0 ]]; then pm_join="$(IFS='; '; echo "${pm[*]}")"; fi

  echo "$bt|$pm_join"
}

ci_type_of_path() {
  local p="$1"
  case "$p" in
    *azure-pipelines.y*ml) echo "azure_devops" ;;
    *.github/workflows/*) echo "github_actions" ;;
    *bamboo-specs/*) echo "bamboo" ;;
    *Jenkinsfile*) echo "jenkins" ;;
    *.travis.yml) echo "travis" ;;
    *bridge.y*ml) echo "bridge_config" ;;
    *) echo "unknown" ;;
  esac
}

invocation_style_of_file() {
  local f="$1"
  if grep_q "$PAT_GHA_ACTION" "$f"; then echo "github_action_synopsys_action"; return; fi
  if grep_q "$PAT_ADO_TASK" "$f"; then
    if grep_q "SynopsysSecurityScan@" "$f"; then echo "ado_task_synopsys_security_scan"; return; fi
    if grep_q "SynopsysBridge@" "$f"; then echo "ado_task_synopsys_bridge"; return; fi
    if grep_q "BlackDuckSecurityScan@" "$f"; then echo "ado_task_blackduck_security_scan"; return; fi
    echo "ado_task_extension"; return
  fi
  if grep_q "$PAT_BRIDGE_CLI" "$f"; then echo "bridge_cli"; return; fi
  if grep_q "$PAT_COVERITY_CLI" "$f"; then echo "coverity_cli"; return; fi
  if grep_q "$PAT_JENKINS_PLUGIN" "$f"; then echo "jenkins_coverity_plugin"; return; fi
  echo "unknown"
}

# Evidence: line-numbered matched lines (limited)
evidence_of_file() {
  local f="$1"
  local pat='polaris|coverity|SynopsysSecurityScan@|SynopsysBridge@|BlackDuckSecurityScan@|synopsys-sig/synopsys-action|--stage[[:space:]]+polaris|--stage[[:space:]]+blackduck|cov-build|cov-analyze|cov-commit-defects'
  awk -v pat="$pat" '
    BEGIN{c=0}
    { if($0 ~ pat){ c++; printf("%d: %s;", NR, $0); if(c>=30) exit } }
  ' "$f" | sed 's/[[:space:]]\+/ /g; s/;$/ /'
}

# ---------------- Azure pipeline transform logic ----------------
# For azure-pipelines.y*ml:
#   - SynopsysBridge@1:
#       bridge_build_type: "polaris" -> "blackduck"
#       polaris_server_url -> blackduck_url: "$(BLACKDUCK_URL)"
#       polaris_access_token -> blackduck_api_token: "$(BLACKDUCK_TOKEN)"
#   - SynopsysSecurityScan@* task:
#       SynopsysSecurityScan@N -> BlackDuckSecurityScan@N
#       scanType: 'polaris' -> 'blackduck'
#
# Apply file handling (your requirement):
#   - Create azure-pipelines_backup.yml/.yaml (fixed name) with ORIGINAL content
#   - Overwrite azure-pipelines.yml/.yaml with migrated content (same name)
#
# Rollback:
#   - Delete migrated azure-pipelines.yml/.yaml
#   - Restore backup azure-pipelines_backup.yml/.yaml -> azure-pipelines.yml/.yaml
#   - Delete azure-pipelines_backup.* after restoring (no leftovers)

ado_transform_content() {
  # args: in_file out_file
  local in_f="$1"
  local out_f="$2"
  cp -f "$in_f" "$out_f"

  # Synopsys Security Scan task transform (best effort)
  sed -Ei \
    -e 's/(\-\s*task:\s*)SynopsysSecurityScan@([0-9]+)/\1BlackDuckSecurityScan@\2/g' \
    -e "s/(scanType:[[:space:]]*)'polaris'/\1'blackduck'/g" \
    -e 's/(displayName:[[:space:]]*")Synopsys Polaris/\1Black Duck/g' \
    "$out_f" 2>/dev/null || true

  # Synopsys Bridge task transform (best effort)
  sed -Ei \
    -e 's/(bridge_build_type:[[:space:]]*)"polaris"/\1"blackduck"/g' \
    "$out_f" 2>/dev/null || true

  # Keys: polaris_server_url -> blackduck_url
  if grep -Eq '^[[:space:]]*polaris_server_url:' "$out_f"; then
    sed -Ei \
      -e 's/^[[:space:]]*polaris_server_url:.*$/      blackduck_url: "$(BLACKDUCK_URL)"/' \
      "$out_f" 2>/dev/null || true
  fi

  # Keys: polaris_access_token -> blackduck_api_token
  if grep -Eq '^[[:space:]]*polaris_access_token:' "$out_f"; then
    sed -Ei \
      -e 's/^[[:space:]]*polaris_access_token:.*$/      blackduck_api_token: "$(BLACKDUCK_TOKEN)"/' \
      "$out_f" 2>/dev/null || true
  fi

  # Cosmetic displayName updates
  sed -Ei \
    -e 's/Synopsys Bridge: Coverity on Polaris/Synopsys Bridge: Black Duck Coverity/g' \
    -e 's/Black Duck Coverity on Polaris/Black Duck Coverity/g' \
    "$out_f" 2>/dev/null || true
}

ado_apply_transform_azure_pipelines() {
  local rel="$1"
  local abs="$ROOT/$rel"
  [[ -f "$abs" ]] || return 1

  # Only act if file contains SynopsysBridge@ or SynopsysSecurityScan@ or polaris markers
  if ! grep -Eq "SynopsysBridge@|SynopsysSecurityScan@|polaris" -- "$abs"; then
    return 1
  fi

  local tmp
  tmp="$(mktemp)"
  ado_transform_content "$abs" "$tmp"

  if cmp -s "$abs" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi

  local backup_abs
  if [[ "$rel" == *".yaml" ]]; then
    backup_abs="$ROOT/azure-pipelines_backup.yaml"
  else
    backup_abs="$ROOT/azure-pipelines_backup.yml"
  fi

  # Create fixed backup only if not already present (protect first original)
  if [[ ! -f "$backup_abs" ]]; then
    cp -f "$abs" "$backup_abs"
    log "[APPLY] Created backup: $(basename "$backup_abs")"
  else
    log "[APPLY] Backup already exists, leaving as-is: $(basename "$backup_abs")"
  fi

  # Overwrite original file with migrated content
  cp -f "$tmp" "$abs"
  rm -f "$tmp"
  log "[APPLY] Updated $rel"
  return 0
}

ado_rollback_transform_azure_pipelines() {
  local rel="$1"
  local abs="$ROOT/$rel"
  [[ "$MODE" == "rollback" ]] || return 1

  local backup_abs
  if [[ "$rel" == *".yaml" ]]; then
    backup_abs="$ROOT/azure-pipelines_backup.yaml"
  else
    backup_abs="$ROOT/azure-pipelines_backup.yml"
  fi

  [[ -f "$backup_abs" ]] || return 1

  # Delete migrated file
  if [[ -f "$abs" ]]; then
    rm -f "$abs"
    log "[ROLLBACK] Deleted migrated: $rel"
  fi

  # Restore backup -> original name
  cp -f "$backup_abs" "$abs"
  log "[ROLLBACK] Restored backup -> $rel"

  # Delete the backup file (your requirement)
  rm -f "$backup_abs"
  log "[ROLLBACK] Deleted backup: $(basename "$backup_abs")"
  return 0
}

# ---------------- CSV + scanning ----------------
list_pipeline_files() {
  (cd "$ROOT" && {
    shopt -s globstar nullglob
    for g in "${PIPELINE_GLOBS[@]}"; do
      for f in $g; do
        [[ -f "$f" ]] && echo "$f"
      done
    done
  }) | sort -u
}

found_type_of() {
  local abs="$1"
  if grep -Eq 'polaris|coverity|SynopsysSecurityScan@|SynopsysBridge@|synopsys-sig/synopsys-action|cov-build|cov-analyze|cov-commit-defects|--stage[[:space:]]+polaris' -- "$abs"; then
    echo "direct"
  else
    echo "none"
  fi
}

append_csv_row() {
  local repo="$1" branch="$2" build_type="$3" pm="$4" rel="$5" ci="$6" found="$7" inv="$8" ev="$9" mig="${10}"

  {
    csv_escape "$repo"; echo -n ","
    csv_escape "$branch"; echo -n ","
    csv_escape "$build_type"; echo -n ","
    csv_escape "$pm"; echo -n ","
    csv_escape "$rel"; echo -n ","
    csv_escape "$ci"; echo -n ","
    echo -n "$found,"
    csv_escape "$inv"; echo -n ","
    csv_escape "$ev"; echo -n ","
    csv_escape "$mig"
    echo
  } >> "$OUT_CSV"
}

migration_changes_for_file() {
  local rel="$1"
  local abs="$ROOT/$rel"

  if [[ "$MODE" == "audit" ]]; then
    if grep -Eq "SynopsysBridge@" -- "$abs"; then
      echo "Change SynopsysBridge Polaris inputs to Black Duck: bridge_build_type: blackduck; set blackduck_url: \$(BLACKDUCK_URL); set blackduck_api_token: \$(BLACKDUCK_TOKEN). Verify credentials/variables."
      return
    fi
    if grep -Eq "SynopsysSecurityScan@" -- "$abs"; then
      echo "Replace SynopsysSecurityScan@* (scanType: polaris) with BlackDuckSecurityScan@* (scanType: blackduck) or your org's Black Duck ADO task; verify service connection fields."
      return
    fi
    echo "Detected Synopsys/Polaris/Coverity markers. Review and migrate to Black Duck / Coverity-in-Polaris per org standards."
    return
  fi

  if [[ "$MODE" == "dry-run" ]]; then
    local before tmp after d
    tmp="$(mktemp)"
    ado_transform_content "$abs" "$tmp"
    d="$(diff -u "$abs" "$tmp" | head -n 200 || true)"
    rm -f "$tmp"
    echo "${d:-NO_DIFF}"
    return
  fi

  # apply/rollback: keep short note
  echo ""
}

# ---------------- Commit / Push ----------------
set_remote_with_token_for_push() {
  [[ "$PUSH" == "1" ]] || return 0
  local url
  url="$(git -C "$ROOT" config --get "remote.${REMOTE}.url" || true)"
  [[ -n "$url" ]] || die "remote.${REMOTE}.url not found"

  # Only rewrite https://github.com/... URLs; if already tokenized, keep.
  if [[ "$url" =~ ^https://github.com/ ]]; then
    local authed="https://x-access-token:${GITHUB_TOKEN}@github.com/${url#https://github.com/}"
    git -C "$ROOT" remote set-url "$REMOTE" "$authed"
  fi
}

commit_and_push_if_needed() {
  local branch="$1"; shift
  local paths=("$@")

  # Determine whether anything changed among the specified paths
  local any_changes=0
  for p in "${paths[@]}"; do
    if [[ -f "$ROOT/$p" || -f "$ROOT/$p" ]]; then
      if ! git -C "$ROOT" diff --quiet -- "$p" 2>/dev/null; then
        any_changes=1
      fi
    fi
  done

  if [[ "$any_changes" -eq 0 ]]; then
    log "[INFO] No changes applied on $branch; skipping commit/push."
    return 0
  fi

  if [[ "$COMMIT" != "1" ]]; then
    log "[INFO] COMMIT=0: changes exist but not committing."
    return 0
  fi

  git -C "$ROOT" config user.email "azure-pipelines@local" || true
  git -C "$ROOT" config user.name "azure-pipelines" || true

  # Stage only pipeline/config files provided
  git -C "$ROOT" add -- "${paths[@]}" || true

  if git -C "$ROOT" diff --cached --quiet; then
    log "[INFO] Nothing staged; skipping commit/push."
    return 0
  fi

  git -C "$ROOT" commit -m "Synopsys â†’ Black Duck migration (${MODE}) [${TS}]" || true

  if [[ "$PUSH" == "1" ]]; then
    set_remote_with_token_for_push
    git -C "$ROOT" push "$REMOTE" "HEAD:$branch"
    log "[INFO] Pushed changes to $branch"
  fi
}

# ---------------- Main ----------------
main() {
  assert_inputs

  # Normalize OUT_CSV to absolute if it isn't (prevents double-prefix bugs)
  if [[ "$OUT_CSV" != /* ]]; then OUT_CSV="$(pwd)/$OUT_CSV"; fi

  ensure_csv_header

  local repo branch info build_type pm
  repo="$(repo_url_of)"
  branch="$(current_branch)"
  info="$(build_info_of_repo)"
  build_type="${info%%|*}"
  pm="${info#*|}"

  local changed_paths=()

  local rel abs ci found inv ev mig
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    abs="$ROOT/$rel"
    [[ -f "$abs" ]] || continue

    ci="$(ci_type_of_path "$rel")"
    found="$(found_type_of "$abs")"
    [[ "$found" == "direct" ]] || continue

    inv="$(invocation_style_of_file "$abs")"
    ev="$(evidence_of_file "$abs")"
    mig="$(migration_changes_for_file "$rel")"

    append_csv_row "$repo" "$branch" "$build_type" "$pm" "$rel" "$ci" "$found" "$inv" "$ev" "$mig"

    # Apply/rollback actions (Azure pipelines only)
    if [[ "$MODE" == "apply" && "$rel" =~ ^azure-pipelines\.ya?ml$ ]]; then
      if ado_apply_transform_azure_pipelines "$rel"; then
        changed_paths+=("$rel")
        # fixed backup name
        if [[ "$rel" == *".yaml" ]]; then
          [[ -f "$ROOT/azure-pipelines_backup.yaml" ]] && changed_paths+=("azure-pipelines_backup.yaml")
        else
          [[ -f "$ROOT/azure-pipelines_backup.yml" ]] && changed_paths+=("azure-pipelines_backup.yml")
        fi
      fi
    fi

    if [[ "$MODE" == "rollback" && "$rel" =~ ^azure-pipelines\.ya?ml$ ]]; then
      if ado_rollback_transform_azure_pipelines "$rel"; then
        changed_paths+=("$rel")
        # backup deleted; do not stage it
      fi
    fi

  done < <(list_pipeline_files)

  # Commit/push only in apply/rollback
  if [[ "$MODE" == "apply" || "$MODE" == "rollback" ]]; then
    if [[ ${#changed_paths[@]} -gt 0 ]]; then
      # De-dup paths
      local uniq=()
      local seen="|"
      local p
      for p in "${changed_paths[@]}"; do
        [[ -n "$p" ]] || continue
        if [[ "$seen" != *"|$p|"* ]]; then
          seen="${seen}${p}|"
          uniq+=("$p")
        fi
      done

      commit_and_push_if_needed "$branch" "${uniq[@]}"
    else
      log "[INFO] No changes applied on $branch; skipping commit/push."
    fi
  fi

  log "Done."
  log "CSV: $OUT_CSV"
  if [[ "$MODE" == "apply" ]]; then
    log "Backup file: azure-pipelines_backup.yml/.yaml (fixed name)"
  fi
}

main "$@"
