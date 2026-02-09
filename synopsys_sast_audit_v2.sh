#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Script: synopsys_sast_audit_v2.sh
# Purpose: SAST-only audit for Synopsys integrations across pipelines + scripts.
#
# CSV Columns:
# repo,branch,build_type,package_manager_file,artifact_type,file_path,ci_type,found_type,invocation_style,script_lines
#
# Multi-branch support:
# - When called multiple times with the same OUT_CSV, it APPENDS rows
# - CSV header is written ONLY ONCE if the file is missing/empty
#
# Build detection (UPDATED for monorepos):
# - Uses git ls-files (tracked + untracked non-ignored) for speed
# - Collects MULTIPLE package manager file PATHS across subfolders (bounded)
# - Adds targeted filesystem fallback to detect marker files even if gitignored
# ============================================================

ROOT="${1:-.}"
OUT_CSV="${2:-synopsys_sast_audit.csv}"

shopt -s globstar nullglob

PIPELINE_GLOBS=(
  "azure-pipelines.yml" "azure-pipelines.yaml"
  ".github/workflows/*.yml" ".github/workflows/*.yaml"
  "Jenkinsfile" "Jenkinsfile*"
  ".travis.yml"
  "bamboo-specs/**/*.yml" "bamboo-specs/**/*.yaml"
  "**/bamboo-specs.yml" "**/bamboo-specs.yaml"
)

WRAPPER_GLOBS=(
  "ci/**/*"
  "scripts/**/*"
  ".ci/**/*"
  ".github/scripts/**/*"
  ".jenkins/**/*"
  ".build/**/*"
  "build/**/*"
  "tools/**/*"
  "devops/**/*"
  "Makefile" "Makefile.*"
  "**/*.sh"
  "**/*.bash"
  "**/*.ps1"
  "**/*.cmd"
  "**/*.bat"
  "**/*.groovy"
  "**/*.gradle"
  "**/*.kts"
  "**/pom.xml"
  "**/build.gradle"
  "**/package.json"
)

# DIRECT markers (already includes bridge/action/ado/coverity/polaris + jenkins plugin markers)
DIRECT_SAST_PATTERN='polaris|coverity|coverity-on-polaris|cov-build|cov-analyze|cov-capture|cov-commit-defects|synopsys[- ]?bridge|bridge(\.exe)?|bridge\.yml|bridge\.yaml|--stage[[:space:]]+polaris|--input[[:space:]]+bridge\.ya?ml|synopsys-sig/synopsys-action|SynopsysSecurityScan@|BlackDuckSecurityScan@|CoverityOnPolaris|polaris\.yml|polaris\.yaml|withCoverityEnv|coverityScan|coverityPublisher|covBuild|covAnalyze|covCommitDefects'

INDIRECT_TEMPLATE_PATTERN='- template:|extends:|resources:|@templates|include:|uses:[[:space:]]*[^[:space:]]+\/[^[:space:]]+@|workflow_call|reusable workflow'
INDIRECT_JENKINS_LIB_PATTERN='@Library\(|library\(|sharedLibrary|vars\/|def[[:space:]]+securityScan|securityScan\(|sastScan\(|polarisScan\(|coverityScan\('
INDIRECT_CONTAINER_PATTERN='docker[[:space:]]+run|container:|image:|services:|podman[[:space:]]+run'

SAST_KEYWORDS_PATTERN='polaris|coverity|synopsys|bridge|sast'

# Write CSV header once
if [[ ! -s "$OUT_CSV" ]]; then
  echo "repo,branch,build_type,package_manager_file,artifact_type,file_path,ci_type,found_type,invocation_style,script_lines" > "$OUT_CSV"
fi

# Safe grep wrappers
grep_q() { grep -Eq "$1" -- "$2" 2>/dev/null; }
grep_in() { grep -Ein "$1" -- "$2" 2>/dev/null || true; }

# CSV sanitize
csv_escape() {
  echo "$1" | sed -E 's/"/""/g' | tr '\n' ' ' | sed -E 's/[[:space:]]+$//'
}

# CI type
ci_type_of() {
  local f="$1"
  if [[ "$f" == *".github/workflows/"* ]]; then echo "github_actions"
  elif [[ "$(basename "$f")" == "azure-pipelines.yml" || "$(basename "$f")" == "azure-pipelines.yaml" ]]; then echo "azure_devops"
  elif [[ "$(basename "$f")" == Jenkinsfile* ]]; then echo "jenkins"
  elif [[ "$(basename "$f")" == ".travis.yml" ]]; then echo "travis"
  elif [[ "$f" == *"bamboo-specs"* ]]; then echo "bamboo"
  else echo "unknown"
  fi
}

# Invocation style
sast_invocation_style() {
  local f="$1"
  if grep_q 'synopsys-sig/synopsys-action' "$f"; then
    echo "github_action_synopsys_action"
  elif grep_q 'withCoverityEnv|coverityScan|coverityPublisher|covBuild|covAnalyze|covCommitDefects' "$f"; then
    echo "jenkins_coverity_plugin_steps"
  elif grep_q 'SynopsysSecurityScan@|BlackDuckSecurityScan@|CoverityOnPolaris' "$f"; then
    echo "ado_task_extension"
  elif grep_q 'synopsys[- ]?bridge|(^|[[:space:]/])bridge([[:space:]]|$)|--stage[[:space:]]+polaris|--input[[:space:]]+bridge\.ya?ml' "$f"; then
    echo "bridge_cli"
  elif grep_q 'cov-build|cov-analyze|cov-capture|cov-commit-defects' "$f"; then
    echo "coverity_cli"
  elif grep_q 'polaris' "$f"; then
    echo "polaris_cli_or_config"
  else
    echo "unknown"
  fi
}

# Evidence lines
script_lines() {
  local f="$1"
  local n=8
  local pat="$DIRECT_SAST_PATTERN|$INDIRECT_TEMPLATE_PATTERN|$INDIRECT_JENKINS_LIB_PATTERN|$INDIRECT_CONTAINER_PATTERN"
  (
    { grep_in "$pat" "$f"; } \
      | head -n "$n" \
      | sed -E 's/"/""/g' \
      | tr '\n' ';' \
      | sed 's/;*$//'
  )
}

# found_type
classify_found_type() {
  local f="$1"

  if grep_q "$DIRECT_SAST_PATTERN" "$f"; then
    echo "direct"; return
  fi

  if grep_q "$INDIRECT_TEMPLATE_PATTERN" "$f" && grep_q "$SAST_KEYWORDS_PATTERN" "$f"; then
    echo "indirect"; return
  fi
  if grep_q "$INDIRECT_JENKINS_LIB_PATTERN" "$f"; then
    echo "indirect"; return
  fi
  if grep_q "$INDIRECT_CONTAINER_PATTERN" "$f" && grep_q "$SAST_KEYWORDS_PATTERN" "$f"; then
    echo "indirect"; return
  fi

  echo "none"
}

# Normalize GitHub URL (ssh -> https)
normalize_repo_url() {
  local url="${1:-}"
  if [[ "$url" =~ ^git@github\.com:(.+)\.git$ ]]; then
    echo "https://github.com/${BASH_REMATCH[1]}"; return
  fi
  if [[ "$url" =~ ^ssh://git@github\.com/(.+)\.git$ ]]; then
    echo "https://github.com/${BASH_REMATCH[1]}"; return
  fi
  if [[ "$url" =~ ^https://github\.com/(.+)\.git$ ]]; then
    echo "https://github.com/${BASH_REMATCH[1]}"; return
  fi
  echo "$url"
}

repo_url_of() {
  local repo="$1"
  local url=""
  if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    url="$(git -C "$repo" config --get remote.origin.url 2>/dev/null || true)"
  fi
  if [[ -z "$url" ]]; then
    echo "$(basename "$repo")"
  else
    normalize_repo_url "$url"
  fi
}

branch_of() {
  local repo="$1"
  local b=""

  if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    b="$(git -C "$repo" branch --show-current 2>/dev/null || true)"
    if [[ -z "$b" ]]; then
      b="$(git -C "$repo" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
    fi
    if [[ -z "$b" || "$b" == "HEAD" ]]; then
      b="$(git -C "$repo" name-rev --name-only --no-undefined HEAD 2>/dev/null || true)"
      b="${b#remotes/origin/}"
      b="${b#origin/}"
      b="${b%%^*}"
    fi
  fi

  [[ -n "$b" && "$b" != "undefined" ]] && echo "$b" || echo "unknown"
}

# Repo file index
repo_file_index() {
  local repo="$1"
  if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$repo" ls-files --cached --others --exclude-standard 2>/dev/null || true
  else
    (cd "$repo" && find . -type f -print 2>/dev/null | sed 's|^\./||') || true
  fi
}

# Targeted fallback search for marker files even if gitignored (kept)
find_first_marker_path() {
  local repo="$1"
  shift
  local -a names=("$@")

  ( cd "$repo" && \
    find . -type f \
      -not -path './.git/*' \
      -not -path '*/.git/*' \
      -not -path '*/node_modules/*' \
      -not -path '*/.gradle/*' \
      -not -path '*/target/*' \
      -not -path '*/build/*' \
      \( $(printf -- '-name %q -o ' "${names[@]}" | sed 's/ -o $//') \) \
      -print 2>/dev/null | head -n 1 | sed 's|^\./||' ) || true
}

# ----------- UPDATED: collect multiple paths per build type (monorepo-aware) -----------
# Limit how many paths we record per type (avoid huge CSV)
MAX_PM_PATHS_PER_TYPE="${MAX_PM_PATHS_PER_TYPE:-10}"

# Collect up to MAX_PM_PATHS_PER_TYPE paths from git-index by regex; fallback to filesystem by file names if none found
collect_paths_with_fallback() {
  local repo="$1"
  local files="$2"
  local regex="$3"
  shift 3
  local -a fallback_names=("$@")

  local out=""
  # From git-index (relative paths)
  out="$(echo "$files" | grep -Ei "$regex" | head -n "$MAX_PM_PATHS_PER_TYPE" || true)"

  # If none, fallback to filesystem (gitignored)
  if [[ -z "$out" && ${#fallback_names[@]} -gt 0 ]]; then
    out="$(cd "$repo" && \
      find . -type f \
        -not -path './.git/*' \
        -not -path '*/.git/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/.gradle/*' \
        -not -path '*/target/*' \
        -not -path '*/build/*' \
        \( $(printf -- '-name %q -o ' "${fallback_names[@]}" | sed 's/ -o $//') \) \
        -print 2>/dev/null | sed 's|^\./||' | head -n "$MAX_PM_PATHS_PER_TYPE" )" || true
  fi

  # Join lines into "; "
  if [[ -n "$out" ]]; then
    echo "$out" | paste -sd ';' - | sed 's/;/; /g'
  else
    echo ""
  fi
}

# Helpers for multi-build detection
add_once() {
  local val="$1"
  local -n arr="$2"
  local x
  for x in "${arr[@]}"; do [[ "$x" == "$val" ]] && return 0; done
  arr+=("$val")
}

# UPDATED build detection: returns build_type + all relevant package manager file PATHS
build_info_of_repo() {
  local repo="$1"
  local files
  files="$(repo_file_index "$repo")"
  [[ -n "$files" ]] || { echo "unknown|unknown"; return; }

  local types=()
  local pm_paths=() # aligned with types

  # Maven
  local maven_paths
  maven_paths="$(collect_paths_with_fallback "$repo" "$files" '(^|/)pom\.xml$|(^|/)(mvnw|mvnw\.cmd)$' "pom.xml" "mvnw" "mvnw.cmd")"
  if [[ -n "$maven_paths" ]]; then
    add_once "maven" types
    pm_paths+=("$maven_paths")
  fi

  # Gradle
  local gradle_paths
  gradle_paths="$(collect_paths_with_fallback "$repo" "$files" '(^|/)(build\.gradle|build\.gradle\.kts|settings\.gradle|settings\.gradle\.kts|gradle\.properties|gradlew|gradlew\.bat)$' \
    "build.gradle" "build.gradle.kts" "settings.gradle" "settings.gradle.kts" "gradle.properties" "gradlew" "gradlew.bat")"
  if [[ -n "$gradle_paths" ]]; then
    add_once "gradle" types
    pm_paths+=("$gradle_paths")
  fi

  # npm / node
  local npm_paths
  npm_paths="$(collect_paths_with_fallback "$repo" "$files" '(^|/)package\.json$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.ya?ml|pnpm-workspace\.ya?ml|lerna\.json|nx\.json|turbo\.json)$' \
    "package.json" "package-lock.json" "yarn.lock" "pnpm-lock.yaml" "pnpm-lock.yml" "pnpm-workspace.yaml" "pnpm-workspace.yml")"
  if [[ -n "$npm_paths" ]]; then
    add_once "npm" types
    pm_paths+=("$npm_paths")
  fi

  # Docker
  local docker_paths
  docker_paths="$(collect_paths_with_fallback "$repo" "$files" '(^|/)Dockerfile$|(^|/)docker-compose\.ya?ml$' "Dockerfile" "docker-compose.yml" "docker-compose.yaml")"
  if [[ -n "$docker_paths" ]]; then
    add_once "docker" types
    pm_paths+=("$docker_paths")
  fi

  # If nothing found
  if [[ ${#types[@]} -eq 0 ]]; then
    echo "unknown|unknown"
    return
  fi

  # Join build types with '+'
  local build_out=""
  local i
  for i in "${!types[@]}"; do
    if [[ -z "$build_out" ]]; then
      build_out="${types[$i]}"
    else
      build_out="${build_out}+${types[$i]}"
    fi
  done

  # Join package manager paths across types with " | " to keep it readable
  # Example: "frontend/package.json; backend/package.json | backend/pom.xml | mobile/android/build.gradle"
  local pm_out=""
  for i in "${!pm_paths[@]}"; do
    if [[ -z "$pm_out" ]]; then
      pm_out="${pm_paths[$i]}"
    else
      pm_out="${pm_out} | ${pm_paths[$i]}"
    fi
  done

  echo "${build_out}|${pm_out}"
}
# ----------- END UPDATED BUILD DETECTION -----------

scan_files_and_report() {
  local repo="$1"
  local repo_url="$2"
  local branch="$3"
  local build_type="$4"
  local pm_file="$5"
  local artifact_type="$6"
  shift 6
  local files=("$@")

  for abs in "${files[@]}"; do
    [[ -f "$abs" ]] || continue
    local rel="${abs#$repo/}"

    # Skip scanning audit tooling itself
    [[ "$rel" == *"synopsys_sast_audit"*".sh"* ]] && continue
    [[ "$rel" == *"bd_detect_audit"*".sh"* ]] && continue

    local found_type
    found_type="$(classify_found_type "$abs")"
    [[ "$found_type" == "none" ]] && continue

    local ci="n/a"
    if [[ "$artifact_type" == "pipeline" ]]; then
      ci="$(ci_type_of "$rel")"
    fi

    local style=""
    if [[ "$found_type" == "direct" ]]; then
      style="$(sast_invocation_style "$abs")"
    fi

    local ex
    ex="$(script_lines "$abs")"

    echo "[${found_type^^}] ${repo_url}@${branch} (build=${build_type}, pm=${pm_file}) :: $rel (artifact=$artifact_type${style:+, style=$style})"

    local repo_e branch_e build_e pm_e rel_e ci_e found_e style_e ex_e
    repo_e="$(csv_escape "$repo_url")"
    branch_e="$(csv_escape "$branch")"
    build_e="$(csv_escape "$build_type")"
    pm_e="$(csv_escape "$pm_file")"
    rel_e="$(csv_escape "$rel")"
    ci_e="$(csv_escape "$ci")"
    found_e="$(csv_escape "$found_type")"
    style_e="$(csv_escape "$style")"
    ex_e="$(csv_escape "$ex")"

    echo "\"$repo_e\",\"$branch_e\",\"$build_e\",\"$pm_e\",\"$artifact_type\",\"$rel_e\",\"$ci_e\",\"$found_e\",\"$style_e\",\"$ex_e\"" >> "$OUT_CSV"
  done
}

audit_repo() {
  local repo="$1"

  local repo_url branch info build_type pm_file
  repo_url="$(repo_url_of "$repo")"
  branch="$(branch_of "$repo")"

  info="$(build_info_of_repo "$repo")"
  build_type="${info%%|*}"
  pm_file="${info#*|}"

  local pipeline_files=()
  for g in "${PIPELINE_GLOBS[@]}"; do
    for f in "$repo"/$g; do
      [[ -f "$f" ]] && pipeline_files+=("$f")
    done
  done
  mapfile -t pipeline_files < <(printf "%s\n" "${pipeline_files[@]}" | awk '!seen[$0]++')

  local wrapper_files=()
  for g in "${WRAPPER_GLOBS[@]}"; do
    for f in "$repo"/$g; do
      [[ -f "$f" ]] && wrapper_files+=("$f")
    done
  done
  mapfile -t wrapper_files < <(printf "%s\n" "${wrapper_files[@]}" | awk '!seen[$0]++')

  if [[ ${#pipeline_files[@]} -eq 0 && ${#wrapper_files[@]} -eq 0 ]]; then
    echo "[INFO] $(basename "$repo"): no files matched for scanning"
    return
  fi

  if [[ ${#pipeline_files[@]} -gt 0 ]]; then
    scan_files_and_report "$repo" "$repo_url" "$branch" "$build_type" "$pm_file" "pipeline" "${pipeline_files[@]}"
  fi
  if [[ ${#wrapper_files[@]} -gt 0 ]]; then
    scan_files_and_report "$repo" "$repo_url" "$branch" "$build_type" "$pm_file" "wrapper_or_script" "${wrapper_files[@]}"
  fi
}

echo "Writing/Updating SAST-only report to: $OUT_CSV"
echo

if [[ -d "$ROOT/.git" ]]; then
  audit_repo "$ROOT"
else
  for d in "$ROOT"/*; do
    [[ -d "$d/.git" ]] || continue
    audit_repo "$d"
  done
fi

echo
echo "Done. CSV: $OUT_CSV"
echo "Interpretation:"
echo " - found_type=direct => Synopsys SAST integration visible (Polaris/Coverity/Bridge/task/action)"
echo " - found_type=indirect => likely via templates/shared libs/container; audit the referenced source"
echo "Build detection note:"
echo " - package_manager_file now lists multiple PATHS across subfolders (monorepo-aware, capped at ${MAX_PM_PATHS_PER_TYPE:-10} per type)"
