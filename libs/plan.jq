include "convert";

def slug: ascii_downcase | gsub("[^a-z0-9]+"; "-") | sub("^-+"; "") | sub("-+$"; "");
def lastseg: split("-") | .[-1];
# Kubernetes names cap at 63 chars. $tail holds the part worth reading ("-backend-1"), so all
# truncation happens in $head.
def fit_tail($head; $tail):
  ((63 - ($tail | length)) | if . < 0 then 0 else . end) as $b
  | (($head[0:$b]) | sub("-+$"; "")) + $tail;
# Truncated but unnumbered when free; -1/-2/... only when the name is already taken.
def take($used; $base):
  fit_tail($base; "") as $c0
  | if (($used | index($c0)) | not) then $c0
    else first(range(1; 1000) | fit_tail($base; "-\(.)")
               | select(. as $c | ($used | index($c)) | not))
    end;
# Over-long minion name: always numbered, tail kept readable. The segment is clamped so the
# tail alone can never exceed 63. ponytail: 999 same-base collisions per run.
def shorttake($used; $sl; $seg):
  first(range(1; 1000)
        | fit_tail("mm-\($sl)"; "-\($seg[0:48] | sub("-+$"; ""))-\(.)")
        | select(. as $c | ($used | index($c)) | not));
def SERVER: ["server-snippets","ssl-redirect","redirect-to-https","http-redirect-code","hsts","hsts-max-age",
             "hsts-include-subdomains","hsts-behind-proxy","server-tokens","ssl-ciphers","ssl-prefer-server-ciphers",
             "app-root","proxy-hide-headers","http2","listen-ports","listen-ports-ssl"];
def SERVERP: SERVER | map("nginx.org/" + .);
# Merge rules that repeat a host, into the first rule for that host, so a host split can see
# all of its paths on one rule. Only rules that actually carry paths participate: a rule with
# no http block is left exactly as it was, never given an empty path list.
def normrules:
  reduce .[] as $r ([];
    ($r.http.paths // null) as $p
    | (map(.host) | index($r.host)) as $i
    | if $r.host != null and $i != null and $p != null then
        .[$i] |= (.http.paths = ((.http.paths // []) + $p))
      else . + [$r] end);
def hostsof: map(.host) | map(select(. != null)) | unique;
def striph($h): map(.hosts |= ((. // []) | map(select(. != $h)))) | map(select((.hosts | length) > 0));
def cls: .spec.ingressClassName // .metadata.annotations["kubernetes.io/ingress.class"] // $class;
def lg($lvl; $ns; $name; $key; $msg): {lvl: $lvl, ns: $ns, name: $name, key: $key, msg: $msg};
def noserver: with_entries(select(.key | IN(SERVERP[]) | not));
def newonly: with_entries(select((.key | startswith("nginx.org/")) and .value != null));

# Every member's spec.tls entry that covers $h, first one winning.
def host_tls($h; $ms):
  $ms | map(.tls | map(select((.hosts // []) | index($h))) | .[0]) | map(select(. != null));

# Server-level annotation values across all members, keyed by annotation, each key holding
# every value seen. More than one value in a list means the members disagree.
def grouped_server_keys($ms):
  [ $ms[] | .ann | to_entries[] | select(.value != null and (.key | IN(SERVERP[]))) ]
  | reduce .[] as $e ({}; .[$e.key] += [$e.value])
  | map_values(dedupe);

# The generated master owns spec.tls and every server-level key; minions keep only paths.
def master_obj($name; $ns; $host; $srv; $tl; $scn; $acn):
  {apiVersion: "networking.k8s.io/v1", kind: "Ingress",
   metadata: {name: $name, namespace: $ns, labels: {"migrate.nginx.org/generated": "true"},
              annotations: ({"nginx.org/mergeable-ingress-type": "master"} + $srv
                            + (if $acn != null then {"kubernetes.io/ingress.class": $acn} else {} end))},
   spec: ((if $scn != null then {ingressClassName: $scn} else {} end)
          + {rules: [{host: $host}]}
          + (if $tl != null then
               {tls: [({hosts: [$host]} + (if $tl.secretName != null then {secretName: $tl.secretName} else {} end))]}
             else {} end))};

# A minion carries only the rules for the shared host, plus the class it came from.
def minion_obj($name; $ns; $rules; $m; $scn; $acn):
  {apiVersion: "networking.k8s.io/v1", kind: "Ingress",
   metadata: {name: $name, namespace: $ns, labels: {"migrate.nginx.org/generated": "true"},
              annotations: (($m.ann | noserver | newonly) + {"nginx.org/mergeable-ingress-type": "minion"}
                            + (if $acn != null then {"kubernetes.io/ingress.class": $acn} else {} end))},
   spec: ((if $scn != null then {ingressClassName: $scn} else {} end) + {rules: $rules})};

def apply_host($c):
  . as $S
  | ($c.ks | map($S.items[.])) as $ms
  | ($ms[0].ing.metadata.namespace) as $ns
  | ($c.h | slug) as $sl
  | ([.creates[].metadata.name]) as $used
  | ("mm-\($sl)" | take($used; .)) as $mname
  | host_tls($c.h; $ms) as $tls
  | ($tls | .[0]) as $tl
  | ([ $tls[] | .secretName // "none" ] | unique) as $secrets
  | (if ($secrets | length) > 1 then
       [lg("WARN"; $ns; $mname; "tls"; "members of host \($c.h) reference different TLS secrets (\($secrets | join(", "))); keeping \($tls[0].secretName // "none") on the master")]
     else [] end) as $tlsconf
  | grouped_server_keys($ms) as $g
  | ($g | to_entries | map(select(.value | length > 1))
       | map(lg("WARN"; $ns; $mname; .key; "conflicting values \(.value | tojson) among members of host \($c.h); first value used on the master"))) as $conf
  | ($g | map_values(.[0])) as $srv
  | ($ms[0].ing | .spec.ingressClassName) as $scn
  | ($ms[0].ing | .metadata.annotations["kubernetes.io/ingress.class"]) as $acn
  | master_obj($mname; $ns; $c.h; $srv; $tl; $scn; $acn) as $master
  | .creates += [$master]
  | .logs += $tlsconf + $conf + [lg("MERGE"; $ns; $master.metadata.name; "host"; "generated master Ingress for host \($c.h) (members: \($c.ks | join(", ")))")]  | reduce $c.ks[] as $k (.;
      .items[$k] as $m
      | ($m.rules | map(select(.host == $c.h))) as $rh
      | ($m.rules | map(select(.host != $c.h))) as $rest
      | ($m.ing.metadata.name) as $nm
      | ([.creates[].metadata.name]) as $used
      | ((if ("mm-\($sl)-\($nm)" | length) <= 63 then take($used; "mm-\($sl)-\($nm)")
          else shorttake($used; $sl; ($nm | lastseg)) end)) as $minname
      | ($m.tls | map(select((.hosts // []) | index($c.h))) | length > 0) as $hadtls
      | ($m.ann | to_entries | map(select((.key | IN(SERVERP[])) and .value != null)) | length > 0) as $hadsrv
      | ([ (if $hadtls then "tls removed" else empty end),
           (if $hadsrv then "server-level keys moved to the master" else empty end) ] | join(", ")) as $moved
      | if ($rest | length) == 0 then
          .items[$k] |= (.ann = ($m.ann | noserver) + {"nginx.org/mergeable-ingress-type": "minion"}
                         | .tls = ($m.tls | striph($c.h)))
          | .logs += [lg("MERGE"; $ns; $nm; "host"; "becomes minion of \($mname)" + (if $moved == "" then "" else "; \($moved)" end))]
        else
          .creates += [minion_obj($minname; $ns; $rh; $m; $scn; $acn)]
          | .items[$k] |= (.rules = $rest | .tls = ($m.tls | striph($c.h)))
          | .logs += [lg("MERGE"; $ns; $nm; "host"; "host \($c.h) split into generated minion \($minname); remaining hosts stay on this Ingress")]
        end);

# Per-Ingress working state, keyed by "namespace/name". $convs holds the matching convert()
# output; a blocked Ingress contributes no annotation patch, so it is left alone entirely.
def index_items($sel; $convs):
  [ range(0; $sel | length) | . as $i | $sel[$i] | {
      key: "\(.metadata.namespace)/\(.metadata.name)",
      value: ($convs[$i] as $cv | {
        k: "\(.metadata.namespace)/\(.metadata.name)", ing: ., conv: $cv, blocked: $cv.block,
        ann: (if $cv.block then {} else $cv.patch end),
        rules: ((.spec.rules // []) | normrules), rules0: (.spec.rules // []),
        tls: (.spec.tls // []), tls0: (.spec.tls // []) }) } ]
  | from_entries;

# Hosts served by more than one Ingress, each with the sorted keys of the Ingresses serving it.
def shared_hosts($items):
  [ $items[] | . as $i | ($i.rules | hostsof[]) | {h: ., k: $i.k} ]
  | reduce .[] as $e ({}; .[$e.h] += [$e.k])
  | to_entries | map({h: .key, ks: (.value | unique)})
  | map(select(.ks | length > 1));

# Merge one shared host, or explain why it is left alone.
def merge_host($items; $c):
  ($c.ks | map($items[.])) as $ms
  # A host with no alphanumerics slugs to "", which would mint a master named "mm" and be
  # shared by every such host in the run. Such a host is not a legal Ingress host either.
  | if ($c.h | slug) == "" then
      .logs += [lg("BLOCK"; "-"; "-"; "host"; "host \($c.h) has no characters usable in an Ingress name; fix or remove the host, not merged")]
    elif ($ms | map(.ing.metadata.namespace) | unique | length) > 1 then
      .logs += [lg("BLOCK"; "-"; "-"; "host"; "host \($c.h) is shared across namespaces (\($c.ks | join(", "))); F5 cannot merge across namespaces, resolve manually")]
    elif ($ms | any(.blocked)) then
      .logs += [lg("WARN"; "-"; "-"; "host"; "host \($c.h) collides but a member is blocked (\($c.ks | join(", "))); not merged")]
    elif ($ms | any(.ing.metadata.annotations["nginx.org/mergeable-ingress-type"] != null)) then
      .logs += [lg("INFO"; "-"; "-"; "host"; "host \($c.h) is already mergeable, left as is")]
    else apply_host($c) end;

# The patch for one Ingress, or null when there is nothing to change. Blocked Ingresses are
# never patched. Emitting only the sections that differ keeps the patch minimal, and an
# empty `tls` becomes an explicit null so the list is removed rather than emptied.
def patch_for($m):
  if $m.blocked then null
  else
    ({metadata: {resourceVersion: $m.ing.metadata.resourceVersion, annotations: $m.ann}}
     + (if $m.rules != $m.rules0 or $m.tls != $m.tls0 then
          {spec: ((if $m.rules != $m.rules0 then {rules: $m.rules} else {} end)
                  + (if $m.tls != $m.tls0
                     then {tls: (if ($m.tls | length) == 0 then null else $m.tls end)}
                     else {} end))}
        else {} end))
    | if ((.metadata.annotations | length) == 0) and (.spec == null) then null else . end
  end;

# The helm warning only makes sense for Ingresses this run actually changes. A row that is
# patched with nothing to report still needs a line: it is the report's own explanation, so it
# belongs in .logs where the summary counts it.
def report_row($m):
  (patch_for($m)) as $p
  | ($m.ing.metadata.annotations["meta.helm.sh/release-name"]) as $rel
  | ($m.conv.logs
     + (if $p != null and $rel != null then
          [lg("WARN"; $m.ing.metadata.namespace; $m.ing.metadata.name; "helm";
              "managed by Helm release \($rel); the next helm upgrade reverts this migration, update the chart")]
        else [] end)) as $logs
  | { ns: $m.ing.metadata.namespace, name: $m.ing.metadata.name, blocked: $m.blocked,
      logs: ($logs
             + (if $p != null and ($logs | length) == 0 then
                  [lg("INFO"; $m.ing.metadata.namespace; $m.ing.metadata.name; "host";
                      "changed by host-collision handling only (see \"Host collision handling\")")]
                else [] end)),
      # untouched pre-migration object: the rollback snapshot migrate.sh writes
      ing: $m.ing,
      patch: $p };

[ .items[]? | select(cls == $class) ] as $sel
| ($sel | map(convert)) as $convs
| (index_items($sel; $convs)) as $items
| {items: $items, creates: [], logs: []} as $S0
| (shared_hosts($items)) as $coll
| (reduce $coll[] as $c ($S0; merge_host($items; $c))) as $S
| { creates: $S.creates,
    logs: $S.logs,
    ingresses: [ $S.items[] | report_row(.) ] }
