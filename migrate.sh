#!/usr/bin/env bash
# Migrate ingress-nginx (community) annotations to F5 NGINX Ingress Controller OSS 5.x.
# Conversion rules live in libs/{convert,lib,plan}.jq. Dry-run by default.

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$SCRIPT_DIR/libs/common.sh"
. "$SCRIPT_DIR/libs/yaml.sh"

NAMESPACE=""
INGRESS_CLASS="nginx"
FROM_FILE=""
SKIP_VALIDATION=false
APPLY=false
PLAN=""
INGRESSES_JSON=""
BACKUP_FILE=""
EXPORT_DIR=""
EXPORT_COUNT=0

usage() {
  echo "Usage: $0 [-n <namespace>] [--class <ingress-class>] [--from-file <ingress-list.json>] [--skip-validation] [--apply]"
}

# Small readers over the plan, so the loops below say what they need rather than how to get it.
row_field() { jq -r ".$1" <<<"$2"; }                                   # $2 is one .ingresses[] row
ref_of()    { jq -r '.metadata.namespace + "/" + .metadata.name' <<<"$1"; }  # $1 is one .creates[] object
patch_of()  { jq -c '.patch | del(.metadata.resourceVersion)' <<<"$1"; }     # $1 is one .ingresses[] row

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -n|--namespace)    [[ $# -ge 2 ]] || { usage; exit 1; }; NAMESPACE=$2; shift ;;
      --class)           [[ $# -ge 2 ]] || { usage; exit 1; }; INGRESS_CLASS=$2; shift ;;
      --from-file)       [[ $# -ge 2 ]] || { usage; exit 1; }; FROM_FILE=$2; shift ;;
      --skip-validation) SKIP_VALIDATION=true ;;
      --apply)           APPLY=true ;;
      -h|--help)         usage; exit 0 ;;
      *) echo "Error: unknown parameter '$1'"; usage; exit 1 ;;
    esac
    shift
  done
}

# Fetch the Ingress list the same way kubectl would report it, so plan.jq owns class selection.
fetch_ingresses() {
  if [[ -n $FROM_FILE ]]; then
    case $FROM_FILE in
      *.yaml|*.yml)
        echo "Error: --from-file takes a JSON Ingress list; YAML input was removed."
        echo "       Run: kubectl get ingress -A -o json > ingress-list.json"
        exit 1 ;;
    esac
    INGRESSES_JSON=$(cat "$FROM_FILE") || exit 1
  else
    local scope
    if [[ -n $NAMESPACE ]]; then scope=(-n "$NAMESPACE"); else scope=(--all-namespaces); fi
    INGRESSES_JSON=$(kubectl get ingress "${scope[@]}" -o json) \
      || { echo "Error: kubectl get ingress failed."; exit 1; }
  fi
  jq -e '.items | type == "array"' <<<"$INGRESSES_JSON" >/dev/null \
    || { echo "Error: input is not an Ingress list (.items missing)."; exit 1; }
}

# --apply across every namespace needs an interactive yes; closed stdin aborts.
confirm_all_namespaces() {
  [[ $APPLY == true && -z $NAMESPACE && -z $FROM_FILE ]] || return 0
  echo "==========================================================="
  echo "SCOPE: ALL NAMESPACES"
  print_scope
  if [[ ! -t 0 ]]; then
    echo "Aborting: --apply across all namespaces needs an interactive terminal; pass -n <namespace> or --from-file."
    exit 1
  fi
  # printf + read, not read -p: the prompt carries no newline, so the closing ruler (and
  # the log, which never sees the typed answer) would run on from the prompt text.
  local confirmation
  printf "Type 'yes' to migrate ALL namespaces above: "
  read -r confirmation || confirmation=""
  echo
  [[ $confirmation == yes ]] || { echo "Aborted."; exit 1; }
  echo "==========================================================="
}

# What is about to change, shown both above the --apply confirmation and in the final summary.
print_scope() {
  jq -r '
    ([.ingresses[].ns, .creates[].metadata.namespace] | unique) as $ns
    | "Namespaces (\($ns | length)): \($ns | join(", "))",
      "Ingresses in class: \(.ingresses | length) | to patch: \([.ingresses[] | select(.patch != null)] | length) | generated: \(.creates | length) | blocked: \([.ingresses[] | select(.blocked)] | length)"' <<<"$PLAN"
}

# Pre-migration snapshot of every selected Ingress, straight from the plan so the
# class filter is applied in exactly one place (libs/plan.jq).
write_backup() {
  BACKUP_FILE=$(unique_path "$BACKUP_ROOT/migrate_backup_$TIMESTAMP.json")
  if ! jq '{items: [.ingresses[].ing]}' <<<"$PLAN" > "$BACKUP_FILE" || [[ ! -s $BACKUP_FILE ]]; then
    echo "Error: cannot write backup '$BACKUP_FILE'; nothing was applied."
    exit 1
  fi
  echo "Backup: $BACKUP_FILE"
}

print_report() {
  echo "==========================================================="
  while IFS= read -r row; do
    print_row "$row"
    echo "-----------------------------------------------------------"
  done < <(jq -c '.ingresses[] | select((.logs | length) > 0 or .patch != null)' <<<"$PLAN")

  echo "Host collision handling:"
  jq -r '.logs[] | "    \(.lvl)  \(.ns)/\(.name) \(.msg)"' <<<"$PLAN"
  echo "-----------------------------------------------------------"
}

# One Ingress: a header, then DROP/WARN/INFO/BLOCK lines, then the MAP lines last so the
# directive mapping reads as the outcome. MAP is also the noisiest level, hence the split.
print_row() {
  local row=$1
  jq -r '"[\(if .blocked then "BLOCKED" else "PLAN" end)] Ingress \(.name) in \(.ns)"' <<<"$row"
  jq -r '.logs[] | select(.lvl != "MAP") | "    \(.lvl)  \(.key): \(.msg)"' <<<"$row"
  jq -r '.logs[] | select(.lvl == "MAP") | "    MAP   \(.key) -> \(.msg)"' <<<"$row"
}

# Server-side dry-run of every planned patch/create. Informational only: dry-run always exits 0.
run_validation() {
  [[ $APPLY == false ]] || return 0
  local valid=0 invalid=0
  if [[ -n $FROM_FILE ]]; then
    echo "INFO: skipping server validation (offline --from-file, no cluster)"
  elif [[ $SKIP_VALIDATION == true ]]; then
    echo "INFO: server validation skipped (--skip-validation)"
  elif ! command -v kubectl >/dev/null; then
    echo "INFO: skipping server validation (kubectl not found)"
  else
    echo "Server validation (kubectl --dry-run=server):"
    local row obj ref err
    while IFS= read -r row; do
      ref="$(row_field ns "$row")/$(row_field name "$row")"
      if err=$(kubectl patch ingress "$(row_field name "$row")" -n "$(row_field ns "$row")" \
                 --type=merge -p "$(patch_of "$row")" --dry-run=server -o name 2>&1); then
        echo "[VALID] $ref"
        valid=$((valid + 1))
      else
        echo "[INVALID] $ref: $(head -n 1 <<<"$err")"
        invalid=$((invalid + 1))
      fi
    done < <(jq -c '.ingresses[] | select(.patch != null)' <<<"$PLAN")

    echo "Generated-name preflight:"
    if check_name_collisions; then
      echo "    [OK] no existing Ingress uses a generated name"
    else
      invalid=$((invalid + 1))
    fi

    while IFS= read -r obj; do
      ref=$(ref_of "$obj")
      if err=$(kubectl apply --dry-run=server -f - <<<"$obj" 2>&1); then
        echo "[VALID] create $ref"
        valid=$((valid + 1))
      else
        echo "[INVALID] create $ref: $(head -n 1 <<<"$err")"
        invalid=$((invalid + 1))
      fi
    done < <(jq -c '.creates[]' <<<"$PLAN")
    echo "-----------------------------------------------------------"
  fi
  echo "Validation  VALID: $valid  INVALID: $invalid"
}

# Names are deterministic, so an unrelated Ingress already holding one would be UPDATED by
# `kubectl apply`, not rejected. Returns 1 when any name is taken or cannot be checked;
# callers decide how loudly. A failed read is never treated as "free": that is the case
# where the guard matters most (RBAC denied, timeout, wrong context).
check_name_collisions() {
  local taken=0 unknown=0 obj name ns existing err
  while IFS= read -r obj; do
    name=$(jq -r '.metadata.name' <<<"$obj"); ns=$(jq -r '.metadata.namespace' <<<"$obj")
    # stderr to a file, never into the value: kubectl warns on stderr during a successful
    # read, and $existing is parsed as JSON below.
    err=$(mktemp)
    if ! existing=$(kubectl get ingress "$name" -n "$ns" --ignore-not-found -o json 2>"$err"); then
      echo "[UNKNOWN] cannot check generated name '$ns/$name': $(head -n 1 "$err")"
      rm -f "$err"
      unknown=$((unknown + 1))
      continue
    fi
    rm -f "$err"
    [[ -n $existing ]] || continue
    # Our own leftovers from an interrupted run are fine: they get applied over.
    [[ $(jq -r '.metadata.labels["migrate.nginx.org/generated"] // ""' <<<"$existing") == true ]] && continue
    echo "[CONFLICT] generated name '$ns/$name' is already used by an existing Ingress that this migration did not create"
    taken=$((taken + 1))
  done < <(jq -c '.creates[]' <<<"$PLAN")
  [[ $taken -eq 0 && $unknown -eq 0 ]]
}

apply_plan() {
  [[ $APPLY == true ]] || return 0
  # Before the first write: a name clash would otherwise silently overwrite someone's Ingress.
  # The line above says which: [CONFLICT] for a taken name, [UNKNOWN] for an unreadable cluster.
  if ! check_name_collisions; then
    echo "Error: refusing to apply; see the [CONFLICT]/[UNKNOWN] line(s) above. Nothing was changed."
    exit 1
  fi
  # Masters before minions, so every minion has a parent when it lands.
  apply_creates master
  apply_patches
  apply_creates minion
}

apply_creates() { # $1: mergeable-ingress-type to create
  local obj
  while IFS= read -r obj; do
    echo "[APPLY] Create $1 $(ref_of "$obj")"
    run_kubectl apply -f - <<<"$obj"
  done < <(jq -c --arg t "$1" '.creates[] | select(.metadata.annotations["nginx.org/mergeable-ingress-type"] == $t)' <<<"$PLAN")
}

apply_patches() {
  local row
  while IFS= read -r row; do
    echo "[APPLY] Patch Ingress '$(row_field name "$row")' in '$(row_field ns "$row")'"
    run_kubectl patch ingress "$(row_field name "$row")" -n "$(row_field ns "$row")" --type=merge -p "$(patch_of "$row")"
  done < <(jq -c '.ingresses[] | select(.patch != null)' <<<"$PLAN")
}

export_one() { # $1: JSON Ingress object -> $EXPORT_DIR/<ns>/<name>.yaml + all.yaml
  local ns name file
  ns=$(jq -r '.metadata.namespace // "default"' <<<"$1")
  name=$(jq -r '.metadata.name' <<<"$1")
  mkdir -p "$EXPORT_DIR/$ns"
  file="$EXPORT_DIR/$ns/$name.yaml"
  # JSON is the last resort only when neither python nor yq nor kubectl is available.
  # The redirect pre-creates the .yaml, so drop it before falling back; a half-written
  # document next to the real .json would fail `kubectl apply -f` on the export dir.
  if ! json_to_yaml <<<"$1" > "$file" || [[ ! -s $file ]]; then
    rm -f "$file"
    file="${file%.yaml}.json"
    printf '%s\n' "$1" > "$file"
  fi
  { printf -- '---\n'; cat "$file"; } >> "$EXPORT_DIR/all.yaml"
  EXPORT_COUNT=$((EXPORT_COUNT + 1))
}

# GitOps export: post-migration manifests as YAML, one file per Ingress plus all.yaml.
export_manifests() {
  [[ $APPLY == true ]] || return 0
  if ! jq -e '([.creates[]] + [.ingresses[] | select(.patch != null)]) | length > 0' <<<"$PLAN" >/dev/null; then
    echo "No changes to export."
    return 0
  fi
  EXPORT_DIR=$(unique_path "$EXPORT_ROOT/migrate_export_$TIMESTAMP")
  mkdir -p "$EXPORT_DIR"
  : > "$EXPORT_DIR/all.yaml"
  EXPORT_COUNT=0

  local obj row ns name
  while IFS= read -r obj; do export_one "$obj"; done < <(jq -c '.creates[]' <<<"$PLAN")
  while IFS= read -r row; do
    ns=$(row_field ns "$row"); name=$(row_field name "$row")
    if obj=$(kubectl get ingress "$name" -n "$ns" -o json 2>/dev/null); then
      obj=$(jq -L "$SCRIPT_DIR/libs" 'include "export"; strip_ephemeral' <<<"$obj")
    else
      # Refetch failed (usually a failed patch): merge the planned patch onto the pre-apply object.
      echo "    WARN: could not refetch $ns/$name; exporting the planned patch instead"
      obj=$(jq -L "$SCRIPT_DIR/libs" -c --argjson row "$row" --arg ns "$ns" --arg name "$name" \
        'include "export"; .items[] | select(.metadata.namespace == $ns and .metadata.name == $name) | merge_patch($row.patch)' <<<"$INGRESSES_JSON")
    fi
    [[ -n $obj ]] && export_one "$obj"
  done < <(jq -c '.ingresses[] | select(.patch != null)' <<<"$PLAN")
  echo "Export: $EXPORT_DIR ($EXPORT_COUNT manifests)"
}

print_summary() {
  echo "==========================================================="
  jq -r '
    # Root logs (host collisions, merge) plus per-Ingress logs; counting only the latter
    # reported WARN: 0 while the body showed helm warnings.
    ([.logs[], .ingresses[].logs[]]) as $l
    | "Ingresses in class: \(.ingresses | length) | to patch: \([.ingresses[] | select(.patch != null)] | length) | unchanged: \([.ingresses[] | select(.patch == null and (.blocked | not))] | length) | generated: \(.creates | length)",
      "Logs  MAP: \($l | map(select(.lvl=="MAP")) | length)  DROP: \($l | map(select(.lvl=="DROP")) | length)  WARN: \($l | map(select(.lvl=="WARN")) | length)  MERGE: \($l | map(select(.lvl=="MERGE")) | length)  INFO: \($l | map(select(.lvl=="INFO")) | length)  BLOCK: \($l | map(select(.lvl=="BLOCK")) | length)",
      (if ([.ingresses[] | select(.blocked)] | length) > 0 then
         "SKIPPED (need manual migration):", ([.ingresses[] | select(.blocked) | "    \(.ns)/\(.name)"] | .[])
       else empty end)' <<<"$PLAN"
  echo "Log: $LOG_FILE"
  if [[ $APPLY == true ]]; then
    if [[ $KUBECTL_FAILURES -eq 0 ]]; then
      echo "Migration completed."
    else
      echo "Migration finished with $KUBECTL_FAILURES failed kubectl call(s)."
      return 1
    fi
  fi
}

main() {
  # Logging first: usage errors and dependency checks must reach the log too.
  init_logging migrate
  init_output_dirs
  parse_args "$@"
  require_cmd jq
  if [[ -z $FROM_FILE ]]; then
    require_cmd kubectl
  elif [[ $APPLY == true ]]; then
    echo "Error: --from-file is offline only and cannot be combined with --apply."
    exit 1
  fi

  echo "Fetching Ingress resources..."
  fetch_ingresses
  PLAN=$(jq -L "$SCRIPT_DIR/libs" --arg class "$INGRESS_CLASS" -f "$SCRIPT_DIR/libs/plan.jq" <<<"$INGRESSES_JSON") \
    || { echo "Error: conversion failed."; exit 1; }

  confirm_all_namespaces

  echo "==========================================================="
  if [[ $APPLY == true ]]; then
    echo "APPLY MODE"
    write_backup
  else
    echo "DRY-RUN: no changes will be made. Use --apply to execute."
  fi
  echo "==========================================================="

  print_report
  run_validation
  apply_plan
  export_manifests
  print_summary
}

main "$@"
