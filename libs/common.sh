#!/usr/bin/env bash
# Shared runtime helpers for migrate.sh and rollback.sh.
# Sourced after SCRIPT_DIR is set; init_logging must run before any output.

# Self-defaulted so an exported override survives sourcing under `set -u`.
TIMESTAMP=${TIMESTAMP:-}
LOG_FILE=""
BACKUP_ROOT=${BACKUP_ROOT:-}
EXPORT_ROOT=${EXPORT_ROOT:-}
TEE_PID=""
KUBECTL_FAILURES=0

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' is required."; exit 1; }
}

# Never clobber a file written by a run in the same second: append -1, -2, ... before the
# extension. A leading dot is part of the name, not an extension, so .gitignore stays intact.
unique_path() {
  local path=$1 dir stem ext candidate n=0
  dir=$(dirname -- "$path")
  stem=$(basename -- "$path")
  ext=""
  if [[ $stem == *.* && $stem != .* ]]; then
    ext=".${stem##*.}"
    stem=${stem%.*}
  fi
  candidate=$path
  while [[ -e $candidate ]]; do
    n=$((n + 1))
    candidate="$dir/${stem}-${n}${ext}"
  done
  printf '%s\n' "$candidate"
}

# Mirror console output into LOG_DIR/<script>_<timestamp>.log.
# The EXIT trap closes our fds first so tee sees EOF, then waits for it to flush:
# without the wait the last line can be lost when the script outruns tee.
init_logging() {
  local script_name=$1
  TIMESTAMP=${TIMESTAMP:-$(date +%Y-%m-%d_%H%M%S)}
  LOG_DIR=${LOG_DIR:-$SCRIPT_DIR/logs}
  mkdir -p "$LOG_DIR"
  LOG_FILE=$(unique_path "$LOG_DIR/${script_name}_${TIMESTAMP}.log")
  exec > >(tee "$LOG_FILE") 2>&1
  TEE_PID=$!
  trap _on_exit EXIT
}

_on_exit() {
  local rc=$?
  [[ -n $TEE_PID ]] || exit "$rc"
  exec 1>&- 2>&-
  wait "$TEE_PID" 2>/dev/null
  exit "$rc"
}

# Paths only; export_manifests creates its own timestamped directory when it runs.
init_output_dirs() {
  BACKUP_ROOT=${BACKUP_ROOT:-$SCRIPT_DIR/backups}
  EXPORT_ROOT=${EXPORT_ROOT:-$SCRIPT_DIR/exports}
  mkdir -p "$BACKUP_ROOT"
}

run_kubectl() { # logs and counts kubectl failures instead of aborting the run
  kubectl "$@" || {
    echo "    FAILED: kubectl $1 $2"
    KUBECTL_FAILURES=$((KUBECTL_FAILURES + 1))
    return 1
  }
}