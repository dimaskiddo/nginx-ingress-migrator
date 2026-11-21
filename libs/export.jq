# Helpers for the GitOps YAML export and the rollback patch.

def strip_ephemeral:
  del(.status,
      .metadata.resourceVersion, .metadata.uid, .metadata.generation,
      .metadata.creationTimestamp, .metadata.managedFields,
      .metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]);

# $p is a PLAN patch. Only used when the post-apply refetch fails; null values in
# the patch mean "delete", which matches how the live object is patched.
def merge_patch($p):
  strip_ephemeral
  | (if $p.spec != null then
       .spec = ((.spec // {}) + $p.spec | with_entries(select(.value != null)))
     else . end)
  | (($p.metadata.annotations // {}) as $pa
     | if ($pa | length) > 0 then
         .metadata.annotations = ((.metadata.annotations // {}) + $pa | with_entries(select(.value != null)))
       else . end);

# Rollback patch: reset both annotation families to the snapshot, and restore spec.rules
# and spec.tls if they drifted. Other annotations (cert-manager, helm, ...) are never
# touched. Emits nothing when the live object already matches the snapshot.
def rollback_patch($snap; $live):
  def ours: with_entries(select(.key | startswith("nginx.ingress.kubernetes.io/") or startswith("nginx.org/")));
  ($snap.metadata.annotations // {} | ours) as $want
  | ($live.metadata.annotations // {} | ours) as $have
  | (reduce (($want | keys[]), ($have | keys[])) as $k ({}; .[$k] = ($want[$k] // null))
     | with_entries(select(.value != $have[.key]))) as $ann
  | ($snap.spec.rules // []) as $want_rules
  | ($snap.spec.tls // []) as $want_tls
  | (if ($live.spec.rules // []) != $want_rules then {rules: $want_rules} else {} end)
    + (if ($live.spec.tls // []) != $want_tls
       then {tls: (if ($want_tls | length) == 0 then null else $want_tls end)}
       else {} end) as $spec
  | {metadata: {annotations: $ann}} + (if ($spec | length) > 0 then {spec: $spec} else {} end)
  | select((.metadata.annotations | length) > 0 or .spec != null);
