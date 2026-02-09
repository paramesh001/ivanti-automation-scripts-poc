#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Inputs / defaults
# -----------------------------
ROOT_DIR="${1:-.}"                      # Path to the cloned target repo
DRY_RUN="${DRY_RUN:-false}"             # true => no file writes, no push
YQ_BIN="${YQ_BIN:-yq}"

# Detect Polaris task IDs
POLARIS_TASK_REGEX="${POLARIS_TASK_REGEX:-^SynopsysPolaris@}"

# Push settings
TARGET_BRANCH="${TARGET_BRANCH:-}"      # If empty, script tries to detect current branch
GITHUB_TOKEN="${GITHUB_TOKEN:-}"        # GitHub PAT (should be injected as secret env var)

# Optional: commit message
COMMIT_MESSAGE="${COMMIT_MESSAGE:-Migrate Polaris pipeline to BlackduckCoverityOnPolaris}"

PIPELINE_PATTERNS=(
  -name "azure-pipelines.yml" -o
  -name "azure-pipelines.yaml" -o
  -name "*pipeline*.yml" -o
  -name "*pipeline*.yaml" -o
  -path "*/.azuredevops/*.yml" -o
  -path "*/.azuredevops/*.yaml" -o
  -path "*/.pipelines/*.yml" -o
  -path "*/.pipelines/*.yaml"
)

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: Missing command: $1" >&2; exit 1; }; }
need_cmd "$YQ_BIN"
need_cmd find
need_cmd python3
need_cmd git
need_cmd base64

echo "Scanning: $ROOT_DIR"
echo "DRY_RUN=$DRY_RUN"
echo "yq version: $("$YQ_BIN" --version 2>&1 || true)"
echo

# -----------------------------
# Replacement stage content
# -----------------------------
STAGE_TMP="$(mktemp)"
cat > "$STAGE_TMP" <<'YAML'
- stage: BlackduckCoverityOnPolaris
  displayName: Blackduck + Coverity on Polaris
  jobs:
  - job: polaris_scan
    displayName: Polaris scan
    steps:
    - task: SynopsysPolaris@1
      inputs:
        polarisService: 'test01'
        polarisCommand: 'polaris'
        waitForIssues: true
        populateChangeSetFile: true

    - task: BlackduckCoverityOnPolaris@2
      inputs:
        polarisService: 'test1'
        polarisCommand: 'polaris'
        waitForIssues: true
        populateChangeSetFile: true
YAML

cleanup() { rm -f "$STAGE_TMP"; }
trap cleanup EXIT

# -----------------------------
# Find pipeline files
# -----------------------------
mapfile -t files < <(find "$ROOT_DIR" -type f \( "${PIPELINE_PATTERNS[@]}" \) 2>/dev/null)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "No pipeline YAML files found."
  exit 0
fi

echo "Found ${#files[@]} candidate pipeline file(s):"
printf ' - %s\n' "${files[@]}"
echo

updated=0
skipped=0

# -----------------------------
# Process each candidate file
# -----------------------------
for f in "${files[@]}"; do
  echo "----"
  echo "Checking file: $f"

  echo "Debug task values found in file:"
  "$YQ_BIN" e '.. | select(tag=="!!map") | .task? | select(.)' "$f" 2>&1 || true

  # Detection using yq (array+length; stable)
  if ! POLARIS_TASK_REGEX="$POLARIS_TASK_REGEX" "$YQ_BIN" e -e \
      '([.. | select(tag=="!!map") | .task? | select(.) | select(test(strenv(POLARIS_TASK_REGEX)))] | length) > 0' \
      "$f" >/dev/null 2>&1; then
    echo "Detection result: NO MATCH -> skipping"
    ((++skipped)) || true
    continue
  fi

  echo "Detection result: MATCH -> processing"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN: would update $f"
    ((++updated)) || true
    continue
  fi

  cp -p "$f" "$f.bak"

  # Transform YAML via Python (more reliable than yq for branching logic)
  POLARIS_TASK_REGEX="$POLARIS_TASK_REGEX" REPL_STAGE_FILE="$STAGE_TMP" python3 - "$f" <<'PY'
import os, re, sys

# PyYAML is commonly present on hosted agents; if not present, fail with a clear message.
try:
    import yaml
except Exception:
    print("ERROR: Python module 'yaml' (PyYAML) is missing on this agent.", file=sys.stderr)
    print("Fix: install PyYAML on the agent (e.g., pip install pyyaml) or use an image with PyYAML.", file=sys.stderr)
    sys.exit(2)

path = sys.argv[1]
regex = re.compile(os.environ["POLARIS_TASK_REGEX"])
repl_stage_file = os.environ["REPL_STAGE_FILE"]

def contains_polaris(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "task" and isinstance(v, str) and regex.search(v):
                return True
            if contains_polaris(v):
                return True
    elif isinstance(obj, list):
        return any(contains_polaris(i) for i in obj)
    return False

def remove_polaris_steps(steps):
    out = []
    for s in steps or []:
        if isinstance(s, dict) and isinstance(s.get("task"), str) and regex.search(s["task"]):
            continue
        out.append(s)
    return out

def mk_legacy_stage(name, display, job, steps):
    return {
        "stage": name,
        "displayName": display,
        "jobs": [{
            "job": job,
            "displayName": display,
            "steps": steps
        }]
    }

with open(path, "r", encoding="utf-8") as f:
    doc = yaml.safe_load(f) or {}

with open(repl_stage_file, "r", encoding="utf-8") as f:
    repl_stages = yaml.safe_load(f) or []
    if not isinstance(repl_stages, list):
        raise ValueError("Replacement stage file must be a YAML list of stages")

changed = False

# CASE 1: stages-based pipeline -> replace all stages containing Polaris
if isinstance(doc.get("stages"), list):
    stages = doc["stages"]
    matches = [i for i, st in enumerate(stages) if contains_polaris(st)]
    if matches:
        insert_at = matches[0]
        kept = [st for st in stages if not contains_polaris(st)]
        doc["stages"] = kept[:insert_at] + repl_stages + kept[insert_at:]
        changed = True

# CASE 2: steps-only pipeline -> convert to stages while preserving root keys
elif isinstance(doc.get("steps"), list):
    steps = doc["steps"]
    first_idx = None
    for i, s in enumerate(steps):
        if isinstance(s, dict) and isinstance(s.get("task"), str) and regex.search(s["task"]):
            first_idx = i
            break

    if first_idx is not None:
        pre = remove_polaris_steps(steps[:first_idx])
        post = remove_polaris_steps(steps[first_idx+1:])

        doc.pop("steps", None)
        new_stages = []
        if pre:
            new_stages.append(mk_legacy_stage("LegacyPre", "Legacy steps (pre)", "legacy_pre", pre))
        new_stages.extend(repl_stages)
        if post:
            new_stages.append(mk_legacy_stage("LegacyPost", "Legacy steps (post)", "legacy_post", post))
        doc["stages"] = new_stages
        changed = True

# If nothing changed, just exit successfully without rewriting
if not changed:
    sys.exit(0)

with open(path, "w", encoding="utf-8") as f:
    yaml.safe_dump(doc, f, sort_keys=False)
PY

  # Only count as updated if file differs from backup
  if ! cmp -s "$f.bak" "$f"; then
    echo "Updated. Backup saved: $f.bak"
    ((++updated)) || true
  else
    echo "No changes made (file identical to backup)."
    ((++skipped)) || true
  fi
done

echo
echo "Done processing files."
echo "Updated: $updated"
echo "Skipped: $skipped"
echo

# -----------------------------
# Commit & push to SAME branch
# -----------------------------
if [[ "$DRY_RUN" == "true" ]]; then
  echo "DRY_RUN=true, skipping commit & push."
  exit 0
fi

cd "$ROOT_DIR"

# If no changes, do nothing
if git diff --quiet; then
  echo "No git changes detected. Nothing to commit/push."
  exit 0
fi

# Determine target branch if not provided
if [[ -z "$TARGET_BRANCH" ]]; then
  # Try to detect current branch
  TARGET_BRANCH="$(git rev-parse --abbrev-ref HEAD || true)"
fi

if [[ -z "$TARGET_BRANCH" || "$TARGET_BRANCH" == "HEAD" ]]; then
  echo "ERROR: Could not determine TARGET_BRANCH (detached HEAD?). Set TARGET_BRANCH env var."
  exit 1
fi

# Need token for push
if [[ -z "$GITHUB_TOKEN" ]]; then
  echo "ERROR: GITHUB_TOKEN is not set. Configure it as an Azure DevOps secret variable and pass via env."
  exit 1
fi

echo "Preparing to commit & push to branch: $TARGET_BRANCH"

# Configure author
git config user.email "pipeline-bot@example.com"
git config user.name  "pipeline-bot"

git add -A

# Commit (if nothing staged, don't fail)
git commit -m "$COMMIT_MESSAGE" || true

# Push using HTTP header auth (avoid putting token in the URL / printing it)
# Azure DevOps guidance: avoid exposing secrets in logs/command line; use secret vars/env. [3](https://www.geeksforgeeks.org/python/how-to-define-and-call-a-function-in-python/)
# GitHub requires token-based auth for HTTPS pushes. [4](https://thebottleneckdev.com/blog/processing-yaml-files)
AUTH_B64="$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')"

# Disable xtrace during push to reduce accidental leakage
set +x
git -c http.extraheader="AUTHORIZATION: basic ${AUTH_B64}" push origin "HEAD:${TARGET_BRANCH}"
set -x

echo "Push completed to branch: ${TARGET_BRANCH}"
