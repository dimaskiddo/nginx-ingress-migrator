#!/usr/bin/env bash
# Rollback for migrate.sh: restores annotations, rules and tls from a JSON backup
# and deletes the master/minion Ingresses that migrate.sh generated.

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$SCRIPT_DIR/libs/common.sh"

SNAPSHOT=""

usage() { echo "Usage: $0 <backup-file.json>"; }

# One wording for every per-Ingress failure; the exit code reports the total.
fail_step() {
  echo "[ERROR] $1"
  KUBECTL_FAILURES=$((KUBECTL_FAILURES + 1))
}

parse_args() {
  [[ $# -eq 1 ]] || { usage; exit 1; }
  SNAPSHOT=$1
}

# A YAML snapshot has to be converted back, and that parser path is gone; say so plainly.
require_json_snapshot() {
  [[ -f $SNAPSHOT ]] || { echo "Error: file '$SNAPSHOT' not found."; exit 1; }
  case $SNAPSHOT in
    *.yaml|*.yml)
      echo "Error: YAML backups are no longer supported; pass the JSON backup written by migrate.sh --apply."
      exit 1 ;;
  esac
  jq -e '.items | type == "array"' "$SNAPSHOT" >/dev/null 2>&1 \
    || { echo "Error: '$SNAPSHOT' is not a kubectl Ingress list (.items missing)."; exit 1; }
}

# Generated Ingresses are not in the backup, so delete them by label in every namespace it covers.
# A failed list would silently leave masters/minions behind while the report says success.
delete_generated() {
  local ns generated err
  while IFS= read -r ns; do
    [[ -n $ns ]] || continue
    # stderr kept out of the value: warnings can arrive on exit 0, and every line here is
    # passed to `kubectl delete` as a resource reference.
    err=$(mktemp)
    if ! generated=$(kubectl get ingress -n "$ns" -l migrate.nginx.org/generated=true -o name 2>"$err"); then
      fail_step "cannot list generated Ingresses in '$ns': $(head -n 1 "$err")"
      rm -f "$err"
      continue
    fi
    rm -f "$err"
    local ref
    while IFS= read -r ref; do
      [[ -n $ref ]] || continue
      echo "[DELETE] generated $ref in '$ns'"
      run_kubectl delete -n "$ns" "$ref"
    done <<<"$generated"
  done < <(jq -r '[.items[].metadata.namespace] | unique[]' "$SNAPSHOT")
}

# Minions must be detached before the original rules/tls come back, so this runs after delete_generated.
restore_snapshots() {
  local ing name ns live patch err
  while IFS= read -r ing; do
    name=$(jq -r '.metadata.name' <<<"$ing")
    ns=$(jq -r '.metadata.namespace' <<<"$ing")

    # stderr kept out: this value is parsed as JSON.
    err=$(mktemp)
    if ! live=$(kubectl get ingress "$name" -n "$ns" -o json --ignore-not-found 2>"$err"); then
      fail_step "cannot read '$name' in '$ns': $(head -n 1 "$err")"
      rm -f "$err"
      continue
    fi
    rm -f "$err"
    if [[ -z $live ]]; then
      fail_step "Ingress '$name' in '$ns' no longer exists; cannot restore it from the snapshot"
      continue
    fi
    if ! patch=$(jq -L "$SCRIPT_DIR/libs" -n -c --argjson s "$ing" --argjson l "$live" \
                   'include "export"; rollback_patch($s; $l)'); then
      fail_step "cannot build a rollback patch for '$name' in '$ns'"
      continue
    fi
    if [[ -z $patch ]]; then
      echo "[SKIP] '$name' in '$ns' already matches the snapshot."
      continue
    fi

    echo "[ROLLBACK] Reverting Ingress '$name' in '$ns'"
    run_kubectl patch ingress "$name" -n "$ns" --type=merge -p "$patch"
  done < <(jq -c '.items[]' "$SNAPSHOT")
}

main() {
  # Logging first: usage errors and dependency checks must reach the log too.
  init_logging rollback
  parse_args "$@"
  require_cmd jq
  require_cmd kubectl
  require_json_snapshot

  echo "==========================================================="
  echo "ROLLBACK from snapshot: $SNAPSHOT"
  echo "==========================================================="

  delete_generated
  restore_snapshots

  echo "==========================================================="
  if [[ $KUBECTL_FAILURES -eq 0 ]]; then
    echo "Rollback completed."
    return 0
  fi
  echo "Rollback finished with $KUBECTL_FAILURES failed step(s)."
  return 1
}

main "$@"
