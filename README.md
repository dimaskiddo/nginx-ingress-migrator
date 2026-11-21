# NGINX Ingress Community to F5 NGINX Ingress Controller OSS Migration Script

Rewrites `nginx.ingress.kubernetes.io/*` annotations as `nginx.org/*` on Ingresses of class
`nginx`, splits hosts that several Ingresses share into mergeable master/minion pairs, and
exports the result as YAML for GitOps. Dry-run by default.

Nothing here talks to F5 directly. It only patches Ingress objects. The controller in
`../Values.yaml` must already be serving IngressClass `nginx`.

## Requirements

| Tool | Needed for |
|------|------------|
| `bash` 5 | everything (`exec > >(tee ...)` PID tracking in `libs/common.sh`) |
| `jq` 1.6+ | conversion pipeline (all rules live in `libs/*.jq`) |
| `kubectl` | live cluster runs; not needed with `--from-file` |
| `python3` + PyYAML | preferred YAML writer for exports |
| `yq` | YAML writer fallback when PyYAML is missing |

Tested against bash 5.2.37, jq 1.7, kubectl 1.36.2, PyYAML 6.0.2, yq 3.4.3 (kislyuk).

## Migrate

```bash
cd scripts

# 1. Look first. Dry-run prints the full plan, changes nothing.
./migrate.sh                                        # all namespaces
./migrate.sh -n my-namespace                        # one namespace
./migrate.sh --class nginx                          # explicit class (this is the default)
./migrate.sh --from-file ingress-list.json          # offline, no cluster needed

# 2. Apply. Writes a backup before it touches anything.
./migrate.sh -n my-namespace --apply
```

`--apply` across every namespace stops and asks you to type `yes`; with no TTY on stdin it
aborts. Pass `-n` or use `--from-file` for unattended runs (the latter cannot be combined
with `--apply`).

Apply order is masters, then patches, then minions, so a minion never lands before its parent.

Generated names are deterministic for a given input list, and follow the master's name:

| | Form | Example |
|---|---|---|
| Master | `mm-<host-slug>` | `mm-projects-example-com` |
| Minion, fits in 63 chars | `mm-<host-slug>-<ingress-name>` | `mm-a-example-com-svc-x` |
| Minion, too long | `mm-<host-slug>-<last-segment>-<N>` | `mm-projects-example-com-backend-1` |

`<last-segment>` is the last `-`-separated segment of the Ingress name. `N` starts at 1 and
increments whenever the same name would be produced twice in one run; a name that merely
needed truncating is used unnumbered. Truncation always eats into the slug so the
`-<segment>-<N>` tail stays readable.

A member that serves only the shared host is converted in place and keeps its own name.

Before changing anything, `--apply` checks that no Ingress outside this migration already
holds one of those names and aborts if it does: `kubectl apply` would otherwise silently
take over someone else's object. Online dry-runs run the same check and report it under
`Generated-name preflight`.

Names depend on the input list's order and membership, unlike a hash scheme. Run the
dry-run and `--apply` against the same cluster state, or use `--from-file` with a captured
snapshot to pin them.

Class selection reads `spec.ingressClassName`, falling back to the
`kubernetes.io/ingress.class` annotation, then to `--class` (default `nginx`). Ingresses of
any other class are ignored entirely: no report lines, no patch, and not in the backup.
`./migrate.sh -h` prints the full flag list.

### Offline preview

```bash
kubectl get ingress -A -o json > ingress-list.json
./migrate.sh --from-file ingress-list.json
```

`--from-file` takes a JSON `{"items": [...]}` list only. YAML input is rejected with a
pointer back to the command above.

### Validation

Without `--apply` and with a live cluster, every planned patch and create is sent through
`kubectl --dry-run=server`. `[INVALID]` lines are informational: a rejected dry-run does
not stop the run, and the summary still reports the counts. Use `--skip-validation` to skip
it, or `--from-file` which skips it automatically.

## Reading the output

```
===========================================================
Ingresses in class: 33 | to patch: 17 | unchanged: 16 | generated: 2
Logs  MAP: 42  DROP: 4  WARN: 17  MERGE: 4  INFO: 13  BLOCK: 0
Log: .../logs/migrate_2026-11-21_040545.log
```

`unchanged` are in-class Ingresses that need nothing done. The `Logs` line counts every
report line, including the host-collision section, so it always reconciles with the body.

| Level | Meaning |
|-------|---------|
| `MAP` | Annotation converted to an `nginx.org/*` key |
| `DROP` | No F5 OSS equivalent; dropped, with the reason |
| `WARN` | Converted, but needs a look (conflicting TLS secrets, Helm-managed, sticky sessions) |
| `INFO` | Nothing to change, or a key folded into another key's output |
| `BLOCK` | Security or traffic control with no equivalent. The Ingress is **not** patched |
| `MERGE` | Generated a master/minion for a shared host |

Every `nginx.ingress.kubernetes.io/*` key on a patched Ingress appears in its own report
block, so a community annotation is never dropped without a line saying so.

A blocked Ingress is not patched and is listed under `SKIPPED (need manual migration)` at
the end. Check the `BLOCK:` count before trusting a clean-looking run. Blocked Ingresses are
still written to the backup, so rollback covers them.

## Rollback

```bash
./rollback.sh backups/migrate_backup_2026-11-21_040545.json
```

Two steps, in this order:

1. Delete every Ingress labelled `migrate.nginx.org/generated=true` in the namespaces the
   snapshot covers (the generated masters/minions).
2. Patch each snapshot Ingress back: both annotation families are reset to their snapshot
   values, `spec.rules` and `spec.tls` are restored if they drifted. Other annotations
   (cert-manager, Helm, ...) are never touched.

Exit code is 1 if any kubectl call failed, so a partial rollback is visible.

Step 1 finds generated Ingresses by the `migrate.nginx.org/generated=true` label, not by
name, so it still works if the naming scheme changes.

## Files written

| Path | When |
|------|------|
| `logs/migrate_<timestamp>.log` | every run, including dry-runs and usage errors |
| `logs/rollback_<timestamp>.log` | every rollback |
| `backups/migrate_backup_<timestamp>.json` | `--apply`, before the first change |
| `exports/migrate_export_<timestamp>/<namespace>/<name>.yaml` | `--apply` |
| `exports/migrate_export_<timestamp>/all.yaml` | `--apply`, all manifests concatenated |

Everything printed to the terminal is mirrored into the log, final line included. Timestamps
are `YYYY-MM-DD_HHMMSS`; a second run in the same second gets `-1`, `-2` appended rather than
overwriting.

`backups/`, `exports/` and `logs/` are gitignored.

### Environment overrides

```bash
LOG_DIR=/tmp/logs BACKUP_ROOT=/tmp/bk EXPORT_ROOT=/tmp/ex ./migrate.sh -n a --apply
TIMESTAMP=2026-11-21_120000 ./migrate.sh -n a --apply   # pin names for reproducible runs
YQ_BIN=/usr/local/bin/yq ./migrate.sh -n a --apply      # pick a specific yq
```

## Layout

```
migrate.sh            plan, validate, apply, export
rollback.sh           restore from a JSON snapshot
test.sh               offline self-check, kubectl stubbed; no cluster needed
libs/common.sh        logging, unique paths, kubectl failure counting
libs/yaml.sh          JSON to YAML for exports (python, then yq, then kubectl)
libs/yaml_json.py     PyYAML writer: block scalars for multi-line strings, input key order
libs/plan.jq          class filter, host collisions, backup/patch plan
libs/convert.jq       per-annotation conversion rules
libs/lib.jq           nginx directive-level snippet conversion
libs/export.jq        strip ephemeral fields, merge patch onto a pre-apply object
```

Cluster state is read once. The class filter lives in `libs/plan.jq` only, so the backup and
the patch plan can never disagree about which Ingresses are in scope.

## Tests

```bash
./test.sh
```

Stubs `kubectl` and `yq`, so it runs offline. Covers conversion rules, blocked cases, the
apply/rollback round trip, export formatting, log completeness and file naming. Ends with
`ALL PASSED` and exits 0 on success.

## Before you apply for real

- Dry-run on the real cluster and read every `WARN` and `BLOCK` line.
- The dry-run and `--apply` must agree: same `to patch` count, same `generated` count, same
  generated names.
- If an earlier version of this script already ran with `--apply`, run `rollback.sh` from
  that run first. The old generated Ingresses carry the same label, so they would linger
  beside the new ones and double-serve the shared host.
- Ingresses managed by Helm (`meta.helm.sh/release-name`) get a `WARN`: the next
  `helm upgrade` will restore the old annotations and strip the master/minion layout.
  Update the chart, not just the live object.
- Roll back with the snapshot from the same run if anything looks wrong.
