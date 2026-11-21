#!/usr/bin/env bash
# JSON -> YAML emitter for the GitOps export.
# Chain: libs/yaml_json.py (stable dump style: block scalars, key order) -> yq -> kubectl.
# Backups and rollback snapshots are JSON, so no YAML parser lives here.

YAML_SH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

have_pyyaml() { python3 -c 'import yaml' >/dev/null 2>&1; }

# Resolved per call so a later YQ_BIN in the same shell takes effect. The two yq projects
# under that name share no flags, and each prints a different --version string:
#   mikefarah v4:  yq (https://github.com/mikefarah/yq/) version v4.44.3
#   kislyuk v3:    yq 3.4.3
yq_flavor() {
  local yq=${YQ_BIN:-yq} v
  command -v "$yq" >/dev/null 2>&1 || { echo none; return; }
  v=$("$yq" --version 2>/dev/null) || { echo unknown; return; }
  case $v in
    *"version v"[0-9]*) echo v4 ;;
    *" "3.*|"yq 3."*)   echo v3 ;;
    *)                  echo unknown ;;
  esac
}

have_yq() { local f; f=$(yq_flavor); [[ $f == v3 || $f == v4 ]]; }

yq_from_json() {
  case $(yq_flavor) in
    v4) "${YQ_BIN:-yq}" -o=yaml --no-colors '.' ;;
    v3) "${YQ_BIN:-yq}" -y '.' ;;
    *)  return 1 ;;
  esac
}

json_to_yaml() { # one JSON object on stdin, YAML document on stdout
  if have_pyyaml; then
    python3 "$YAML_SH_DIR/yaml_json.py"
  elif have_yq; then
    yq_from_json
  else
    # Last resort: kubectl is already a dependency of every cluster run.
    kubectl create --dry-run=client -o yaml -f - 2>/dev/null
  fi
}
