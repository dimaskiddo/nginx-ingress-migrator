#!/usr/bin/env bash
# Offline self-check for migrate.sh / rollback.sh. No cluster needed (kubectl is stubbed).
#
# Each section writes a fixture under $T and runs the real plan.jq or migrate.sh over it.
# Assertions read the plan through these accessors instead of inline jq:
#   plan_of <file>            run libs/plan.jq over an Ingress-list JSON file
#   annot <ingress> <key>     patched nginx.org annotation, or __none__
#   blocked <ingress>         .blocked for an Ingress in the main fixture
#   merge <ingress>           the root MERGE log line for that Ingress
#   created <name>            a generated Ingress name, empty unless it was created
#   inplace <ingress>         mergeable-ingress-type the patch sets, or __none__
#   message <ingress>         the root log line for an Ingress in the names fixture
#   field <ingress> <jq-path> any field of a row in the regression plan
set -uo pipefail
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d); export LOG_DIR=$T/logs; trap 'rm -rf "$T"' EXIT
fail=0
ok() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
plan_of() { jq -L "$DIR/libs" --arg class nginx -f "$DIR/libs/plan.jq" "$1"; }

P="nginx.ingress.kubernetes.io/"
NL=$'\n'
cat > "$T/in.json" <<EOF
{"items":[
 {"metadata":{"name":"full","namespace":"a","resourceVersion":"1","annotations":{
   "${P}configuration-snippet":"more_clear_headers \"X-Frame-Options\";\nmore_set_headers \"X-Frame-Options: DENY\" \"Content-Security-Policy: frame-ancestors 'none'; img-src a, b\";\nproxy_set_header Host \$host;\nproxy_set_header X-Custom 1;",
   "${P}whitelist-source-range":"10.0.0.0/8, 1.2.3.4",
   "${P}denylist-source-range":"9.9.9.9/32",
   "${P}server-snippet":"location /x { return 200; }",
   "${P}use-regex":"“true”",
   "${P}rewrite-target":"/\$2",
   "${P}upstream-hash-by":"\$connection_upgrade",
   "${P}proxy-body-size":"10m",
   "${P}proxy-read-timeout":"60",
   "${P}backend-protocol":"GRPCS",
   "${P}force-ssl-redirect":"true",
   "${P}limit-rps":"10",
   "${P}add-headers":"x=y",
   "${P}ssl-protocols":"TLSv1.2",
   "${P}made-up-key":"1"}},
  "spec":{
   "tls":[{"hosts":["h1"]}],
   "rules":[{"host":"h1","http":{"paths":[{"path":"/","backend":{"service":{"name":"s1","port":{"number":80}}}}]}}]}},

 {"metadata":{"name":"ss","namespace":"a","resourceVersion":"7","annotations":{"${P}server-snippet":"keepalive_timeout 300s; client_body_timeout 300s;"}},"spec":{"rules":[{"host":"h5"}]}},
 {"metadata":{"name":"sec","namespace":"a","resourceVersion":"2","annotations":{"${P}auth-url":"http://x","${P}proxy-read-timeout":"5"}},"spec":{"rules":[{"host":"h2"}]}},
 {"metadata":{"name":"badcidr","namespace":"a","resourceVersion":"3","annotations":{"${P}whitelist-source-range":"10.0.0.0/99"}},"spec":{"rules":[{"host":"h3"}]}},
 {"metadata":{"name":"other","namespace":"a","resourceVersion":"4","annotations":{"${P}proxy-read-timeout":"5"}},"spec":{"ingressClassName":"alb","rules":[{"host":"h4"}]}},
 {"metadata":{"name":"c1","namespace":"b","resourceVersion":"5"},"spec":{"tls":[{"hosts":["shared"],"secretName":"s"}],"rules":[{"host":"shared","http":{"paths":[{"path":"/a","backend":{"service":{"name":"x","port":{"number":1}}}}]}}]}},
 {"metadata":{"name":"c2","namespace":"b","resourceVersion":"6","annotations":{"${P}ssl-redirect":"true"}},"spec":{"tls":[{"hosts":["shared"],"secretName":"s"}],"rules":[{"host":"shared","http":{"paths":[{"path":"/b","backend":{"service":{"name":"y","port":{"number":1}}}}]}}]}}
]}
EOF

"$DIR/migrate.sh" --from-file "$T/in.json" > "$T/out.txt" 2>&1
rc=$?
ok "dry-run exits 0 even with blocked ingresses" "[ $rc -eq 0 ]"
ok "offline dry-run skips server validation" 'grep -q "skipping server validation (offline" "$T/out.txt" && ! grep -q "\[VALID\]" "$T/out.txt"'
python3 -c 'import json,sys,yaml; d=json.load(open(sys.argv[1])); yaml.safe_dump_all(d["items"], sys.stdout, sort_keys=False)' "$T/in.json" > "$T/in.yaml"
"$DIR/migrate.sh" --from-file "$T/in.yaml" > "$T/out_yaml.txt" 2>&1 ; rc=$?
ok "--from-file rejects a YAML list" '[ $rc -ne 0 ] && grep -q "YAML input was removed" "$T/out_yaml.txt"'
PLAN=$(plan_of "$T/in.json")
annot()  { jq -r --arg n "$1" ".ingresses[] | select(.name==\$n) | .patch.metadata.annotations[\"$2\"] // \"__none__\"" <<<"$PLAN"; }
blocked(){ jq -r --arg n "$1" '.ingresses[] | select(.name==$n) | .blocked' <<<"$PLAN"; }
merge()  { jq -r --arg n "$1" '.logs[] | select(.name==$n) | .msg' <<<"$PLAN"; }
ok "bare timeout gets unit"            '[ "$(annot full nginx.org/proxy-read-timeout)" = "60s" ]'
ok "proxy-body-size renamed"           '[ "$(annot full nginx.org/client-max-body-size)" = "10m" ]'
ok "smart-quote use-regex -> path-regex" '[ "$(annot full nginx.org/path-regex)" = "case_insensitive" ]'
ok "rewrite-target kept"               '[ "$(annot full nginx.org/rewrite-target)" = "/\$2" ]'
ok "upstream-hash-by -> lb-method"     '[ "$(annot full nginx.org/lb-method)" = "hash \$connection_upgrade consistent" ]'
ok "GRPCS sets grpc and ssl services"  '[ "$(annot full nginx.org/grpc-services)" = s1 ] && [ "$(annot full nginx.org/ssl-services)" = s1 ]'
ok "force-ssl-redirect + 308"          '[ "$(annot full nginx.org/ssl-redirect)" = True ] && [ "$(annot full nginx.org/http-redirect-code)" = 308 ]'
ok "limit-rps converted"               '[ "$(annot full nginx.org/limit-req-rate)" = "10r/s" ] && [ "$(annot full nginx.org/limit-req-burst)" = 50 ]'
LS=$(annot full nginx.org/location-snippets)
ok "acl: deny, allow, deny all"        '[[ $LS == *"deny 9.9.9.9/32;"*"allow 10.0.0.0/8;"*"allow 1.2.3.4;"*"deny all;"* ]]'
ok "multi-arg more_set_headers split"  '[[ $LS == *"add_header X-Frame-Options \"DENY\" always;"* && $LS == *"add_header Content-Security-Policy \"frame-ancestors '"'"'none'"'"'; img-src a, b\" always;"* ]]'
ok "more_clear_headers -> hide"        '[[ $LS == *"proxy_hide_header X-Frame-Options;"* ]]'
ok "default Host header dropped"       '[[ $LS != *"proxy_set_header Host"* ]]'
ok "custom proxy_set_header kept"      '[[ $LS == *"proxy_set_header X-Custom 1;"* ]]'
ok "server-snippet loc directives moved" '[ "$(annot ss nginx.org/location-snippets)" = "keepalive_timeout 300s;${NL}client_body_timeout 300s;" ] && [ "$(annot ss nginx.org/server-snippets)" = __none__ ]'
ok "server-only block stays in server-snippets" '[[ "$(annot full nginx.org/server-snippets)" == *"location /x"* ]]'
ok "no more_* left in output"          '[[ $LS != *more_* ]]'
ok "old keys nulled"                   '[ "$(jq -r ".ingresses[]|select(.name==\"full\")|.patch.metadata.annotations|[to_entries[]|select(.key|startswith(\"nginx.ingress\"))|.value]|all(.==null)" <<<"$PLAN")" = true ]'
ok "add-headers/ssl-protocols/unknown logged as DROP" '[ "$(jq "[.ingresses[]|select(.name==\"full\")|.logs[]|select(.lvl==\"DROP\")]|length" <<<"$PLAN")" -ge 3 ]'
ok "auth-url blocks ingress, no patch" '[ "$(jq -r ".ingresses[]|select(.name==\"sec\")|.patch==null" <<<"$PLAN")" = true ] && [ "$(blocked sec)" = true ]'
ok "invalid CIDR blocks"               '[ "$(blocked badcidr)" = true ]'
ok "other ingress class ignored"       '[ "$(jq "[.ingresses[]|select(.name==\"other\")]|length" <<<"$PLAN")" = 0 ]'
ok "host collision -> 1 master"        '[ "$(jq "[.creates[]|select(.metadata.annotations[\"nginx.org/mergeable-ingress-type\"]==\"master\")]|length" <<<"$PLAN")" = 1 ]'
ok "members become minions, tls removed" '[ "$(jq -r "[.ingresses[]|select(.name==\"c1\" or .name==\"c2\")|.patch.metadata.annotations[\"nginx.org/mergeable-ingress-type\"]==\"minion\" and .patch.spec.tls==null]|all" <<<"$PLAN")" = true ]'
ok "in-place msg lists only what moved (tls)" '[ "$(merge c1)" = "becomes minion of mm-shared; tls removed" ]'
ok "in-place msg lists only what moved (tls + keys)" '[ "$(merge c2)" = "becomes minion of mm-shared; tls removed, server-level keys moved to the master" ]'
ok "ssl-redirect moved to master only" '[ "$(jq -r ".creates[]|select(.metadata.name|startswith(\"mm-\"))|.metadata.annotations[\"nginx.org/ssl-redirect\"]" <<<"$PLAN")" = True ] && [ "$(annot c2 nginx.org/ssl-redirect)" = __none__ ]'
ok "every patch is valid JSON with resourceVersion" '[ "$(jq -r "[.ingresses[]|select(.patch!=null)|.patch.metadata.resourceVersion!=null]|all" <<<"$PLAN")" = true ]'

# real backup, if present: only known F5 keys may be emitted
REAL=$(ls "$DIR"/backups/*.json 2>/dev/null | head -1)
if [[ -n $REAL ]]; then
  KNOWN='proxy-connect-timeout proxy-read-timeout proxy-send-timeout proxy-next-upstream
    proxy-next-upstream-timeout proxy-next-upstream-tries client-max-body-size
    client-body-buffer-size proxy-buffering proxy-buffers proxy-buffer-size
    proxy-busy-buffers-size proxy-max-temp-file-size path-regex rewrite-target
    upstream-vhost ssl-ciphers ssl-prefer-server-ciphers app-root ssl-redirect
    redirect-to-https http-redirect-code lb-method ssl-services grpc-services
    websocket-services use-cluster-ip sticky-cookie-services proxy-http-version
    proxy-redirect-from proxy-redirect-to location-snippets server-snippets
    limit-req-rate limit-req-burst limit-req-no-delay limit-req-reject-code
    mergeable-ingress-type'
  KNOWN=$(tr -s ' \n' ' ' <<<"$KNOWN")
  BAD=$(plan_of "$REAL" \
    | jq -r --arg known "$KNOWN" '[.ingresses[].patch.metadata.annotations // {} | keys[] | select(startswith("nginx.org/")) | ltrimstr("nginx.org/")] | unique - ($known | split(" ")) | .[]')
  ok "real backup emits only known nginx.org keys" '[ -z "$BAD" ]'
  ok "real backup holds only class nginx" '[ "$(jq -c "[.items[] | (.spec.ingressClassName // .metadata.annotations[\"kubernetes.io/ingress.class\"])] | unique" "$REAL")" = "[\"nginx\"]" ]'
fi

# conversion regressions from the bug sweep.
# The last two share one over-long host: master naming plus conflicting tls secrets.
LONGH=this-is-a-deliberately-very-long-shared-hostname-for-the-63-char-check.example.com
cat > "$T/bug.json" <<EOF
{"items":[
 {"metadata":{"name":"brace","namespace":"a","resourceVersion":"1","annotations":{"${P}configuration-snippet":"if (\$x) { auth_request /auth; }"}},"spec":{"rules":[{"host":"b1"}]}},
 {"metadata":{"name":"hash","namespace":"a","resourceVersion":"1","annotations":{"${P}configuration-snippet":"proxy_set_header X-A 1; # trailing note\nmore_set_headers \"X-B: 2\";"}},"spec":{"rules":[{"host":"b2"}]}},
 {"metadata":{"name":"frag","namespace":"a","resourceVersion":"1","annotations":{"${P}permanent-redirect":"https://h/#frag"}},"spec":{"rules":[{"host":"b3"}]}},
 {"metadata":{"name":"cookie","namespace":"a","resourceVersion":"1","annotations":{"${P}proxy-cookie-domain":"a; evil;"}},"spec":{"rules":[{"host":"b4"}]}},
 {"metadata":{"name":"v6","namespace":"a","resourceVersion":"1","annotations":{"${P}whitelist-source-range":"1::2/999"}},"spec":{"rules":[{"host":"b5"}]}},
 {"metadata":{"name":"numrange","namespace":"a","resourceVersion":"1","annotations":{"${P}whitelist-source-range":123,"${P}proxy-read-timeout":"30"}},"spec":{"rules":[{"host":"b6"}]}},
 {"metadata":{"name":"baddur","namespace":"a","resourceVersion":"1","annotations":{"${P}proxy-connect-timeout":"abc"}},"spec":{"rules":[{"host":"b7"}]}},
 {"metadata":{"name":"badbuf","namespace":"a","resourceVersion":"1","annotations":{"${P}proxy-request-buffering":"bogus"}},"spec":{"rules":[{"host":"b8"}]}},
 {"metadata":{"name":"long","namespace":"a","resourceVersion":"1","annotations":{"${P}ssl-redirect":"true"}},"spec":{"tls":[{"hosts":["${LONGH}"],"secretName":"s1"}],"rules":[{"host":"${LONGH}"}]}},
 {"metadata":{"name":"long2","namespace":"a","resourceVersion":"1","annotations":{"${P}ssl-redirect":"true"}},"spec":{"tls":[{"hosts":["${LONGH}"],"secretName":"s2"}],"rules":[{"host":"${LONGH}"}]}}
]}
EOF
BP=$(plan_of "$T/bug.json")
field() { jq -r --arg n "$1" ".ingresses[] | select(.name==\$n) | $2" <<<"$BP"; }
ok "brace-wrapped auth is blocked"    '[ "$(field brace .blocked)" = true ]'
ok "inline # comment is stripped"     '[[ "$(field hash .patch.metadata.annotations[\"nginx.org/location-snippets\"])" != *#* ]]'
ok "other directives survive comment" '[[ "$(field hash .patch.metadata.annotations[\"nginx.org/location-snippets\"])" == *"X-B"* ]]'
ok "#fragment redirect is dropped"    '[ "$(field frag ".patch.metadata.annotations[\"nginx.org/location-snippets\"] // \"__none__\"")" = __none__ ] && [[ "$(field frag "[.logs[]|.lvl]")" == *DROP* ]]'
ok "cookie-domain injection blocked"  '[ "$(field cookie .blocked)" = true ]'
ok "IPv6 prefix >128 blocked"         '[ "$(field v6 .blocked)" = true ]'
ok "numeric range blocked, rest kept" '[ "$(field numrange .blocked)" = true ]'
ok "bad duration blocked"             '[ "$(field baddur .blocked)" = true ]'
ok "bad buffering blocked"            '[ "$(field badbuf .blocked)" = true ]'
ok "generated names fit 63 chars"     '[ "$(jq -r "[.creates[]|.metadata.name|length<=63]|all" <<<"$BP")" = true ]'
ok "conflicting tls secrets warned"   '[ "$(jq -r "[.logs[]|select(.lvl==\"WARN\" and .key==\"tls\")]|length" <<<"$BP")" -ge 1 ]'
# the report must name the object that will exist, not the untruncated 70-char name
ok "MERGE messages use the fitted name" '[ "$(jq -r "[.creates[].metadata.name as \$n | ([.logs[].msg] + [.ingresses[].logs[].msg] | join(\" \") | contains(\$n))] | all" <<<"$BP")" = true ]'
ok "no over-long generated name in any message" '[ "$(jq -r "[.logs[].msg, .ingresses[].logs[].msg] | map([scan(\"mm-[a-z0-9-]+\")] | map(select(length > 63)) | length) | add" <<<"$BP")" = 0 ]'
ok "every root-log name is a real object" '[ "$(jq -r "([.logs[].name] - [\"-\"] - [.creates[].metadata.name] - [.ingresses[].name]) | length" <<<"$BP")" = 0 ]'

# every community annotation must appear in its own Ingress report block
cat > "$T/silent.json" <<'EOF'
{"items":[
 {"metadata":{"name":"sil","namespace":"a","resourceVersion":"1","annotations":{
   "nginx.ingress.kubernetes.io/session-cookie-name":"SESS",
   "nginx.ingress.kubernetes.io/limit-burst-multiplier":"3",
   "nginx.ingress.kubernetes.io/denylist-source-range":"9.9.9.9/32",
   "nginx.ingress.kubernetes.io/limit-rps":"5"}},"spec":{"rules":[{"host":"s1"}]}}
]}
EOF
SP=$(plan_of "$T/silent.json")
ok "orphan session-cookie key is reported" '[ "$(jq -r "[.ingresses[].logs[]|select(.key==\"session-cookie-name\")]|length" <<<"$SP")" -ge 1 ]'
ok "limit-burst-multiplier is reported"    '[ "$(jq -r "[.ingresses[].logs[]|select(.key==\"limit-burst-multiplier\")]|length" <<<"$SP")" -ge 1 ]'
ok "denylist-source-range is reported"     '[ "$(jq -r "[.ingresses[].logs[]|select(.key==\"denylist-source-range\")]|length" <<<"$SP")" -ge 1 ]'
ok "every community key appears in report" '[ "$(jq -r "[.ingresses[]|select(.patch!=null)|([.ing.metadata.annotations|keys[]|select(startswith(\"nginx.ingress.kubernetes.io/\"))] - ([.logs[].key]|map(\"nginx.ingress.kubernetes.io/\"+.)))|length>0]|any|not" <<<"$SP")" = true ]'

# generated-name scheme: mm-<host>-<ingress-name>, shortened to mm-<host>-<last-segment>-<N>
N3=$(printf 'a%.0s' $(seq 49)); N4=$(printf 'b%.0s' $(seq 49))
TAIGA_BE=collaboration-tools-taiga-ingress-backend
TAIGA_FE=collaboration-tools-taiga-ingress-frontend
cat > "$T/names.json" <<EOF
{"items":[
 {"metadata":{"name":"${TAIGA_BE}","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"projects.example.com"},{"host":"other.example.com"}]}},
 {"metadata":{"name":"${TAIGA_FE}","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"projects.example.com"}]}},
 {"metadata":{"name":"pad-${N3}-backend","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"h2.example.com"},{"host":"h3.example.com"}]}},
 {"metadata":{"name":"pad-${N4}-backend","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"h2.example.com"},{"host":"h4.example.com"}]}},
 {"metadata":{"name":"svc-x","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"a.example.com"},{"host":"a-example.com"},{"host":"tail.example.com"}]}},
 {"metadata":{"name":"svc-y","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"a.example.com"},{"host":"a-example.com"},{"host":"tail.example.com"}]}},
 {"metadata":{"name":"x-backend","namespace":"c","resourceVersion":"1","annotations":{"${P}ssl-ciphers":"ECDHE-RSA-AES256-GCM-SHA384"}},"spec":{"rules":[{"host":"${LONGH}"},{"host":"z.example.com"}]}},
 {"metadata":{"name":"y-backend","namespace":"c","resourceVersion":"1","annotations":{"${P}ssl-ciphers":"ECDHE-RSA-AES128-GCM-SHA256"}},"spec":{"rules":[{"host":"${LONGH}"}]}}
]}
EOF
NP=$(plan_of "$T/names.json")
created() { jq -r --arg n "$1" '.creates[]|select(.metadata.name==$n)|.metadata.name' <<<"$NP"; }
inplace() { jq -r --arg n "$1" '.ingresses[]|select(.name==$n)|.patch.metadata.annotations["nginx.org/mergeable-ingress-type"] // "__none__"' <<<"$NP"; }
message() { jq -r --arg n "$1" '.logs[]|select(.name==$n)|.msg' <<<"$NP"; }
ok "short minion is mm-<host>-<seg>-1"  '[ "$(created mm-projects-example-com-backend-1)" = mm-projects-example-com-backend-1 ]'
ok "master keeps mm-<host> form"        '[ "$(created mm-projects-example-com)" = mm-projects-example-com ]'
ok "in-place minion keeps its name"     '[ -z "$(created $TAIGA_FE)" ] && [ "$(inplace $TAIGA_FE)" = minion ]'
ok "bare in-place message has no false clause" '[ "$(message $TAIGA_FE)" = "becomes minion of mm-projects-example-com" ]'
ok "same segment short names get -1 and -2" '[ "$(created mm-h2-example-com-backend-1)" = mm-h2-example-com-backend-1 ] && [ "$(created mm-h2-example-com-backend-2)" = mm-h2-example-com-backend-2 ]'
ok "slug-identical hosts bump the master" '[ "$(created mm-a-example-com)" = mm-a-example-com ] && [ "$(created mm-a-example-com-1)" = mm-a-example-com-1 ]'
ok "taken full form keeps name, bumps counter" '[ "$(created mm-a-example-com-svc-x-1)" = mm-a-example-com-svc-x-1 ] && [ "$(created mm-a-example-com-svc-y-1)" = mm-a-example-com-svc-y-1 ] && [ "$(created mm-a-example-com-svc-x)" = mm-a-example-com-svc-x ]'
ok "long slug keeps the -seg-N tail"    '[ "$(jq -r "[.creates[].metadata.name|select(startswith(\"mm-this-\") and endswith(\"-backend-1\"))]|length" <<<"$NP")" = 1 ]'
ok "generated names are unique in one run" '[ "$(jq -r "([.creates[].metadata.name]|length) == ([.creates[].metadata.name]|unique|length)" <<<"$NP")" = true ]'
ok "generated names are valid DNS-1123"  '[ "$(jq -r "[.creates[].metadata.name|test(\"^[a-z0-9]([-a-z0-9]*[a-z0-9])?\$\")]|all" <<<"$NP")" = true ]'
# a tail longer than the whole budget must still produce a valid, short name
cat > "$T/hugeseg.json" <<EOF
{"items":[
 {"metadata":{"name":"$(printf 'z%.0s' $(seq 70))","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"h.example.com"},{"host":"w.example.com"}]}},
 {"metadata":{"name":"filler","namespace":"c","resourceVersion":"1"},"spec":{"rules":[{"host":"h.example.com"}]}}
]}
EOF
HUGESEG=$(plan_of "$T/hugeseg.json")
ok "over-long segment tail is clamped"  '[ "$(jq -r "[.creates[].metadata.name|length<=63]|all" <<<"$HUGESEG")" = true ] && [ "$(jq -r ".creates|length" <<<"$HUGESEG")" = 2 ]'
ok "name generation is deterministic"   '[ "$(jq -r "[.creates[].metadata.name]" <<<"$NP")" = "$(plan_of "$T/names.json" | jq -r "[.creates[].metadata.name]")" ]'
ok "every root-log name is a real object (names fixture)" '[ "$(jq -r "([.logs[].name] - [\"-\"] - [.creates[].metadata.name] - [.ingresses[].name]) | length" <<<"$NP")" = 0 ]'
ok "conflicting values warn names the master" '[ "$(jq -r "[.logs[]|select(.lvl==\"WARN\" and .key==\"nginx.org/ssl-ciphers\")]|length" <<<"$NP")" -ge 1 ] && [ "$(jq -r "[.logs[]|select(.lvl==\"WARN\" and .key==\"nginx.org/ssl-ciphers\")|.name|startswith(\"mm-this-\") and (length<=63)]|all" <<<"$NP")" = true ]'

# a host with no alphanumerics slugs to "", which used to mint a master named "mm"
cat > "$T/emptyslug.json" <<'EOF'
{"items":[
 {"metadata":{"name":"u1","namespace":"a","resourceVersion":"1"},"spec":{"rules":[{"host":"___"}]}},
 {"metadata":{"name":"u2","namespace":"a","resourceVersion":"1"},"spec":{"rules":[{"host":"___"}]}}
]}
EOF
ES=$(plan_of "$T/emptyslug.json")
ok "host with no usable characters is blocked" '[ "$(jq -r "[.logs[]|select(.lvl==\"BLOCK\" and .key==\"host\")]|length" <<<"$ES")" -ge 1 ]'
ok "host with no usable characters creates nothing" '[ "$(jq -r ".creates|length" <<<"$ES")" = 0 ]'

# duplicate-host rules: merging is reported, and a rule with no http is never given paths
cat > "$T/duprule.json" <<'EOF'
{"items":[
 {"metadata":{"name":"merge","namespace":"a","resourceVersion":"1"},"spec":{"rules":[
   {"host":"d.example.com","http":{"paths":[{"path":"/one","backend":{"service":{"name":"s","port":{"number":80}}}}]}},
   {"host":"d.example.com","http":{"paths":[{"path":"/two","backend":{"service":{"name":"s","port":{"number":80}}}}]}}]}},
 {"metadata":{"name":"nohttp","namespace":"a","resourceVersion":"1"},"spec":{"rules":[
   {"host":"n.example.com"},{"host":"n.example.com"}]}}
]}
EOF
DR=$(plan_of "$T/duprule.json")
ok "duplicate-host rules are merged into one" '[ "$(jq -r ".ingresses[]|select(.name==\"merge\")|.patch.spec.rules|length" <<<"$DR")" = 1 ]'
ok "merged rule keeps both paths" '[ "$(jq -r ".ingresses[]|select(.name==\"merge\")|.patch.spec.rules[0].http.paths|length" <<<"$DR")" = 2 ]'
ok "rule with no http is not given empty paths" '[ "$(jq -r ".ingresses[]|select(.name==\"nohttp\")|.patch" <<<"$DR")" = null ]'
ok "merge-only patch carries a counted INFO line" '[ "$(jq -r "[.ingresses[]|select(.name==\"merge\")|.logs[]|select(.lvl==\"INFO\")]|length" <<<"$DR")" -ge 1 ]'

# snippet messages must not claim a conversion that produced nothing
cat > "$T/snip.json" <<'EOF'
{"items":[
 {"metadata":{"name":"noop","namespace":"a","resourceVersion":"1","annotations":{"nginx.ingress.kubernetes.io/configuration-snippet":"# nothing here"}},"spec":{"rules":[{"host":"n1"}]}},
 {"metadata":{"name":"pbuf","namespace":"a","resourceVersion":"1","annotations":{"nginx.ingress.kubernetes.io/proxy-request-buffering":"off"}},"spec":{"rules":[{"host":"n2"}]}},
 {"metadata":{"name":"buffoff","namespace":"a","resourceVersion":"1","annotations":{"nginx.ingress.kubernetes.io/proxy-buffering":"off","nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers":"false"}},"spec":{"rules":[{"host":"n3"}]}}
]}
EOF
SN=$(plan_of "$T/snip.json")
ok "empty snippet does not claim conversion" '[ "$(jq -r "[.ingresses[]|select(.name==\"noop\")|.logs[]|select(.lvl==\"MAP\" and (.msg|contains(\"converted\")))]|length" <<<"$SN")" = 0 ]'
ok "blocked snippet does not claim conversion" '[ "$(jq -r "[.ingresses[]|select(.name==\"brace\")|.logs[]|select(.lvl==\"MAP\" and (.msg|contains(\"converted\")))]|length" <<<"$BP")" = 0 ]'
ok "proxy_request_buffering msg keeps the semicolon" '[ "$(jq -r ".ingresses[]|select(.name==\"pbuf\")|.logs[]|select(.key==\"proxy-request-buffering\")|.msg" <<<"$SN")" = "location-snippets: proxy_request_buffering off;" ]'
# a community string value must be decoded before it is emitted: "off" is truthy in jq
ok "proxy-buffering off becomes False"  '[ "$(jq -r ".ingresses[]|select(.name==\"buffoff\")|.patch.metadata.annotations[\"nginx.org/proxy-buffering\"]" <<<"$SN")" = False ]'
ok "ssl-prefer-server-ciphers false becomes False" '[ "$(jq -r ".ingresses[]|select(.name==\"buffoff\")|.patch.metadata.annotations[\"nginx.org/ssl-prefer-server-ciphers\"]" <<<"$SN")" = False ]'

# a quoted header value must not be able to escape its own quotes
cat > "$T/prefix.json" <<'EOF'
{"items":[
 {"metadata":{"name":"esc","namespace":"a","resourceVersion":"1","annotations":{
   "nginx.ingress.kubernetes.io/x-forwarded-prefix":"x\\"}},"spec":{"rules":[{"host":"p1"}]}},
 {"metadata":{"name":"fine","namespace":"a","resourceVersion":"1","annotations":{
   "nginx.ingress.kubernetes.io/x-forwarded-prefix":"/api"}},"spec":{"rules":[{"host":"p2"}]}}
]}
EOF
PX=$(plan_of "$T/prefix.json")
ok "prefix ending in backslash is blocked" '[ "$(jq -r ".ingresses[]|select(.name==\"esc\")|.blocked" <<<"$PX")" = true ]'
ok "blocked prefix emits no snippet"       '[ "$(jq -r ".ingresses[]|select(.name==\"esc\")|.patch" <<<"$PX")" = null ]'
ok "ordinary prefix still maps"            '[ "$(jq -r ".ingresses[]|select(.name==\"fine\")|.patch.metadata.annotations[\"nginx.org/location-snippets\"]" <<<"$PX")" = "proxy_set_header X-Forwarded-Prefix \"/api\";" ]'

# rollback against a kubectl stub that serves $T/live.json
mkdir -p "$T/bin"
cat > "$T/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
case $1 in
  get) if [[ " $* " == *" -l "* ]]; then cat "$STUB_DIR/generated.txt"; else jq -c --arg n "$3" '.items[]|select(.metadata.name==$n)' "$STUB_DIR/live.json"; fi ;;
  patch) echo "$*" >> "$STUB_DIR/calls.txt" ;;
  delete) echo "$*" >> "$STUB_DIR/calls.txt" ;;
esac
EOF
chmod +x "$T/bin/kubectl"
jq -c '{items: [.items[0] | .metadata.annotations = {"nginx.org/proxy-read-timeout":"60s","nginx.org/leftover":"x","cert-manager.io/issuer":"i"} | .spec.tls = []]}' "$T/in.json" > "$T/live.json"
jq -c '{items: [.items[0] | .metadata.annotations["cert-manager.io/issuer"]="i"]}' "$T/in.json" > "$T/backup.json"
echo "ingress.networking.k8s.io/mm-shared" > "$T/generated.txt"
STUB_DIR=$T PATH="$T/bin:$PATH" "$DIR/rollback.sh" "$T/backup.json" > "$T/rb.txt" 2>&1 ; rc=$?
ok "rollback exits clean"                '[ $rc -eq 0 ] || grep -q "Rollback completed" "$T/rb.txt"'
ok "rollback deletes generated ingress"  'grep -q "delete -n a ingress.networking.k8s.io/mm-shared" "$T/calls.txt"'
ok "rollback nulls nginx.org keys"       'grep -q "\"nginx.org/leftover\":null" "$T/calls.txt"'
ok "rollback restores community keys"    'grep -q "nginx.ingress.kubernetes.io/proxy-body-size" "$T/calls.txt"'
ok "rollback leaves cert-manager alone"  '! grep -q "cert-manager" "$T/calls.txt"'
ok "rollback restores tls"               'grep -q "\"tls\":\[{\"hosts\":\[\"h1\"\]}\]" "$T/calls.txt"'

ok "rollback patch has no resourceVersion" '! grep -q "resourceVersion" "$T/calls.txt"'

# rollback only accepts the JSON snapshot written by migrate.sh --apply
python3 -c 'import json,sys,yaml; d=json.load(open(sys.argv[1])); yaml.safe_dump_all(d["items"], sys.stdout, sort_keys=False)' "$T/backup.json" > "$T/backup.yaml"
: > "$T/calls.txt"
STUB_DIR=$T PATH="$T/bin:$PATH" "$DIR/rollback.sh" "$T/backup.yaml" > "$T/rb2.txt" 2>&1 ; rc=$?
ok "rollback rejects a YAML snapshot"    '[ $rc -ne 0 ] && grep -q "YAML backups are no longer supported" "$T/rb2.txt"'
ok "rejected rollback touches nothing"   '[ ! -s "$T/calls.txt" ]'

# rollback must not report success when the snapshot cannot be applied
mkdir -p "$T/failbin"
cat > "$T/failbin/kubectl" <<'EOF'
#!/usr/bin/env bash
case $1 in
  get) if [[ " $* " == *" -l "* ]]; then echo "Error from server: stubbed list failure" >&2; exit 1; fi
       jq -c --arg n "$3" '.items[]|select(.metadata.name==$n)' "$STUB_DIR/live.json" ;;
  patch|delete) echo "$*" >> "$STUB_DIR/calls.txt" ;;
esac
EOF
chmod +x "$T/failbin/kubectl"
STUB_DIR=$T PATH="$T/failbin:$PATH" "$DIR/rollback.sh" "$T/backup.json" > "$T/rb3.txt" 2>&1 ; rc=$?
ok "failed generated-list is an error"   '[ $rc -ne 0 ] && grep -q "cannot list generated" "$T/rb3.txt"'
: > "$T/live.json"
STUB_DIR=$T PATH="$T/failbin:$PATH" "$DIR/rollback.sh" "$T/backup.json" > "$T/rb4.txt" 2>&1 ; rc=$?
ok "missing original is not a success"   '[ $rc -ne 0 ] && grep -q "no longer exists" "$T/rb4.txt"'

# export merge/strip helper: the patch nulls one key and one whole section, and both
# must disappear from the exported manifest while unrelated annotations survive.
LIVE='{
 "metadata":{"name":"x","namespace":"a","resourceVersion":"1","uid":"u","annotations":{
   "nginx.ingress.kubernetes.io/proxy-body-size":"10m",
   "keep":"me"}},
 "spec":{"tls":[{"hosts":["h"]}]},
 "status":{}}'
PATCH='{
 "metadata":{"resourceVersion":"1","annotations":{
   "nginx.ingress.kubernetes.io/proxy-body-size":null,
   "nginx.org/client-max-body-size":"10m"}},
 "spec":{"tls":null}}'
OUT=$(jq -L "$DIR/libs" -c --argjson p "$PATCH" 'include "export"; merge_patch($p)' <<<"$LIVE")
ok "export strips ephemerals"     '[ "$(jq -r "has(\"status\") or (.metadata|has(\"resourceVersion\") or has(\"uid\"))" <<<"$OUT")" = false ]'
ok "export removes community key" '[ "$(jq -r ".metadata.annotations|has(\"nginx.ingress.kubernetes.io/proxy-body-size\")" <<<"$OUT")" = false ]'
ok "export adds nginx.org key"    '[ "$(jq -r ".metadata.annotations[\"nginx.org/client-max-body-size\"]" <<<"$OUT")" = 10m ]'
ok "export keeps other annotation" '[ "$(jq -r ".metadata.annotations.keep" <<<"$OUT")" = me ]'
ok "export null patch removes tls" '[ "$(jq -r ".spec|has(\"tls\")" <<<"$OUT")" = false ]'

# shared YAML emitter: block scalars for multi-line strings, quoting kept for scalars like "true"
YOUT=$(printf '{"metadata":{"annotations":{"s":"a\\nb\\n","t":"true"}}}' | python3 "$DIR/libs/yaml_json.py")
ok "YAML dump uses block scalars"  'grep -q "^    s: |$" <<<"$YOUT" && ! grep -q "s: .a" <<<"$YOUT"'
ok "YAML dump keeps quoting"       'grep -q "^    t: .true.$" <<<"$YOUT"'

# libs/yaml.sh: JSON -> YAML emit chain (python -> yq -> kubectl)
. "$DIR/libs/yaml.sh"
. "$DIR/libs/common.sh"
YJ='{"metadata":{"annotations":{"s":"a\nb","t":"true"}}}'
ok "json_to_yaml via python"        '[[ "$(json_to_yaml <<<"$YJ")" == *"    s: |-"*"    t: '"'"'true'"'"'"* ]]'
# yq 4.x flag branch (only kislyuk 3.x is installed here): python blocked so yq must carry it
mkdir -p "$T/v4" "$T/nopy"
for b in jq dirname kubectl bash env; do
  p=$(command -v $b) && ln -sf "$p" "$T/nopy/$b"
done
cat > "$T/v4/yq" <<'EOF'
#!/usr/bin/env bash
# mikefarah v4 flag surface, backed by the installed kislyuk yq
case $1 in
  --version) echo "yq (https://github.com/mikefarah/yq/) version v4.44.3"; exit 0 ;;
  -o=yaml)   shift; exec /usr/bin/yq -y '.' ;;
  *)         exec /usr/bin/yq -c '.' ;;
esac
EOF
chmod +x "$T/v4/yq"
ok "yq v4 flags are detected"       '[ "$(YQ_BIN=$T/v4/yq yq_flavor)" = v4 ]'
ok "json_to_yaml falls back to yq"  '[ -n "$(PATH="$T/nopy" YQ_BIN=$T/v4/yq json_to_yaml <<<"$YJ")" ]'
ERR=$(PATH="$T/nopy" YQ_BIN=nonexistent-yq bash -c ". '$DIR/libs/yaml.sh'; json_to_yaml" <<<"$YJ" 2>&1); rc=$?
ok "no YAML emitter fails cleanly"  '[ $rc -ne 0 ] && [ -z "$ERR" ]'

# libs/common.sh: same-second runs must not clobber each other's logs or backups
: > "$T/dup.log"
ok "unique_path avoids clobber"     '[ "$(unique_path "$T/dup.log")" = "$T/dup-1.log" ]'

# --apply: confirmation gate, YAML backup, GitOps export
mkdir -p "$T/kbin" "$T/backups" "$T/exports"
cat > "$T/kbin/kubectl" <<'EOF'
#!/usr/bin/env bash
case $1 in
  get)
    case " $* " in
      *" -l "*) cat "$STUB_DIR/generated.txt"; exit 0 ;;
      *" --all-namespaces "*) cat "$STUB_DIR/live.json"; exit 0 ;;
    esac
    if [[ $3 == -* ]]; then cat "$STUB_DIR/live.json"
    else jq -c --arg n "$3" '.items[] | select(.metadata.name==$n)' "$STUB_DIR/post.json"; fi ;;
  apply|patch)
    if [[ " $* " == *" --dry-run=server "* ]]; then
      cat > /dev/null
      echo "$*" >> "$STUB_DIR/vcalls.txt"
      target=""
      case " $* " in *" ingress "*) target="${3}" ;; esac
      if [[ -n ${STUB_FAIL:-} && $* == *"$STUB_FAIL"* ]]; then
        echo "Error from server: stubbed invalid" >&2; exit 1
      fi
      exit 0
    fi
    cat > /dev/null; echo "$*" >> "$STUB_DIR/calls.txt" ;;
  delete) echo "$*" >> "$STUB_DIR/calls.txt" ;;
esac
EOF
chmod +x "$T/kbin/kubectl"
cat > "$T/live.json" <<'EOF'
{"items":[
 {"apiVersion":"networking.k8s.io/v1",
  "kind":"Ingress",
  "metadata":{
    "name":"app","namespace":"a","resourceVersion":"9","uid":"u",
    "creationTimestamp":"2026-01-01T00:00:00Z",
    "annotations":{
      "nginx.ingress.kubernetes.io/proxy-body-size":"10m",
      "cert-manager.io/issuer":"i"}},
  "spec":{
    "tls":[{"hosts":["app.example"],"secretName":"s"}],
    "rules":[{"host":"app.example","http":{"paths":[
      {"path":"/","pathType":"Prefix",
       "backend":{"service":{"name":"svc","port":{"number":80}}}}]}}]},
  "status":{"loadBalancer":{}}}
]}
EOF
# what the cluster reports after the patch: conversion applied, ephemerals gone
jq -c '{items:[.items[0] | .status={} | .metadata.annotations = {
        "nginx.org/client-max-body-size":"10m",
        "nginx.org/location-snippets":"a;\nb;",
        "cert-manager.io/issuer":"i"}]}' "$T/live.json" > "$T/post.json"
: > "$T/calls.txt"
STUB_DIR=$T PATH="$T/kbin:$PATH" LOG_DIR=$T/logs BACKUP_ROOT=$T/backups EXPORT_ROOT=$T/exports \
  "$DIR/migrate.sh" --apply < /dev/null > "$T/a1.txt" 2>&1 ; rc=$?
ok "apply all-namespaces without TTY aborts" '[ $rc -ne 0 ] && grep -q "Aborting" "$T/a1.txt"'
ok "abort touches nothing" '[ ! -s "$T/calls.txt" ] && [ -z "$(ls -A "$T/backups")" ]'

STUB_DIR=$T PATH="$T/kbin:$PATH" LOG_DIR=$T/logs BACKUP_ROOT=$T/backups EXPORT_ROOT=$T/exports \
  "$DIR/migrate.sh" --apply -n a > "$T/a2.txt" 2>&1 ; rc=$?
ok "apply -n exits 0" '[ $rc -eq 0 ]'
ok "apply patches the ingress" 'grep -q "patch ingress app -n a" "$T/calls.txt"'
ok "apply patch has no resourceVersion" '! grep -q "resourceVersion" "$T/calls.txt"'
ok "all-namespaces EOF never hits unbound var" '! grep -q "unbound variable" "$T/a1.txt"'
ok "apply backup is JSON" 'ls "$T"/backups/migrate_backup_*.json >/dev/null 2>&1 && ! ls "$T"/backups/*.yaml >/dev/null 2>&1'
ok "backup holds exactly the class-nginx fetch" '[ "$(jq -r ".items|length" "$T"/backups/migrate_backup_*.json)" = 1 ] && [ "$(jq -r ".items[0].metadata.name" "$T"/backups/migrate_backup_*.json)" = app ]'
ok "backup keeps pre-migration annotations" '[ "$(jq -r ".items[0].metadata.annotations[\"nginx.ingress.kubernetes.io/proxy-body-size\"]" "$T"/backups/migrate_backup_*.json)" = 10m ]'
ok "export writes per-namespace file" '[ -s "$T"/exports/migrate_export_*/a/app.yaml ]'
ok "export has no resourceVersion" '! grep -q "resourceVersion" "$T"/exports/migrate_export_*/a/app.yaml'
ok "export carries nginx.org key" 'grep -q "client-max-body-size" "$T"/exports/migrate_export_*/a/app.yaml'
# an emitter that writes part of a document then fails must not leave the .yaml behind
# (migrate.sh's export_one is the code under test; drive it with a failing emitter)
EXPD=$(mktemp -d "$T/exp.XXXXXX")
(
  . "$DIR/libs/common.sh"
  EXPORT_DIR=$EXPD; EXPORT_COUNT=0
  json_to_yaml() { printf 'metadata:\n  name: partial'; return 1; }
  eval "$(sed -n '/^export_one()/,/^}/p' "$DIR/migrate.sh")"
  export_one '{"metadata":{"name":"x","namespace":"a"}}'
)
ok "failed emitter leaves no stale .yaml" '[ ! -e "$EXPD/a/x.yaml" ]'
ok "failed emitter falls back to JSON"    '[ -s "$EXPD/a/x.json" ]'

# logging: everything on the console must also be in the log, including the last line
APPLY_LOG=$(sed -n 's/^Log: //p' "$T/a2.txt")
ok "apply run reports its log file" '[ -f "$APPLY_LOG" ]'
ok "console output is fully logged" 'diff -q "$T/a2.txt" "$APPLY_LOG" >/dev/null'
ok "log captures the final line"    'grep -q "Migration completed." "$APPLY_LOG"'
ok "log captures the summary"       'grep -q "Ingresses in class:" "$APPLY_LOG"'
ok "log name is migrate_<iso timestamp>" '[[ $(basename "$APPLY_LOG") =~ ^migrate_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}(-[0-9]+)?\.log$ ]]'
ok "backup name is migrate_backup_<iso timestamp>" '[[ $(basename "$T"/backups/migrate_backup_*.json) =~ ^migrate_backup_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}(-[0-9]+)?\.json$ ]]'
ok "export dir is migrate_export_<iso timestamp>" '[[ $(basename "$(ls -d "$T"/exports/migrate_export_* | head -1)") =~ ^migrate_export_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}(-[0-9]+)?$ ]]'
ok "rollback log is rollback_<iso timestamp>" 'ls "$T"/logs/rollback_*.log | grep -Eq "rollback_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}(-[0-9]+)?\.log$"'
"$DIR/migrate.sh" --bogus > "$T/badarg.txt" 2>&1
ok "argument errors are logged"     'grep -q "unknown parameter" "$T/badarg.txt" && grep -rq "unknown parameter" "$T"/logs/'
ok "backup drops out-of-class ingresses" '[ "$(jq -r "[.items[].metadata.name] | unique - [\"app\"] | length" "$T"/backups/migrate_backup_*.json)" = 0 ]'

# summary must reconcile with the report body: root logs (MERGE/WARN) count too
ok "summary reports unchanged count" 'grep -q "unchanged: 0" "$T/a2.txt"'
ok "summary counts root logs"        'grep -q "MERGE: 0" "$T/a2.txt"'
ok "summary line uses Logs label"    'grep -q "^Logs  MAP:" "$T/a2.txt"'
BODYW=$(grep -cE '^    (WARN|MERGE|INFO|DROP)  ' "$T/a2.txt" || true)
SUMALL=$(sed -n 's/^Logs .*WARN: \([0-9]*\).*MERGE: \([0-9]*\).*INFO: \([0-9]*\).*/\1 \2 \3/p' "$T/a2.txt" | awk '{print $1+$2+$3}')
ok "summary WARN+MERGE+INFO matches body" '[ "$BODYW" = "$SUMALL" ]'

# helm-managed Ingress that needs no collision merge must still be warned
cat > "$T/helm.json" <<'EOF'
{"items":[
 {"metadata":{"name":"h","namespace":"a","resourceVersion":"1","annotations":{
   "nginx.ingress.kubernetes.io/proxy-body-size":"5m",
   "meta.helm.sh/release-name":"rel"}},"spec":{"rules":[{"host":"hx"}]}}
]}
EOF
cat > "$T/helm2.json" <<'EOF'
{"items":[
 {"metadata":{"name":"h","namespace":"a","resourceVersion":"1",
   "annotations":{"meta.helm.sh/release-name":"rel"}},"spec":{"rules":[{"host":"hx"}]}}
]}
EOF
HP=$(plan_of "$T/helm.json")
ok "non-collision helm ingress is warned" '[ "$(jq -r "[.ingresses[].logs[]|select(.lvl==\"WARN\" and .key==\"helm\")]|length" <<<"$HP")" = 1 ]'
HIP=$(plan_of "$T/helm2.json")
ok "unchanged helm ingress is not warned" '[ "$(jq -r "[.ingresses[].logs[]|select(.key==\"helm\")]|length" <<<"$HIP")" = 0 ]'

# a row with a patch but no conversion logs must still say something in its own block
cat > "$T/mm.json" <<'EOF'
{"items":[
 {"metadata":{"name":"c1","namespace":"b","resourceVersion":"5"},"spec":{"rules":[{"host":"sh","http":{"paths":[{"path":"/a","backend":{"service":{"name":"x","port":{"number":1}}}}]}}]}},
 {"metadata":{"name":"c2","namespace":"b","resourceVersion":"6"},"spec":{"rules":[{"host":"sh","http":{"paths":[{"path":"/b","backend":{"service":{"name":"y","port":{"number":1}}}}]}}]}}
]}
EOF
LOG_DIR=$T/logs "$DIR/migrate.sh" --from-file "$T/mm.json" > "$T/mm.txt" 2>&1
ok "merge-only patch carries an INFO line" 'grep -q "host-collision handling only" "$T/mm.txt"'

# generated-name preflight: an existing unrelated Ingress on the generated name must abort --apply
mkdir -p "$T/cbin"
cat > "$T/cbin/kubectl" <<'EOF'
#!/usr/bin/env bash
case $1 in
  get) case " $* " in
         *" -l "*) cat "$STUB_DIR/generated.txt" ;;
         *" --all-namespaces "*) cat "$STUB_DIR/collive.json" ;;
         *) if [[ $3 == -* ]]; then cat "$STUB_DIR/collive.json"
            else cat "$STUB_DIR/squat.json"; fi ;;
       esac ;;
  apply|patch|delete) echo "$*" >> "$STUB_DIR/calls.txt"; cat > /dev/null ;;
esac
EOF
chmod +x "$T/cbin/kubectl"
cat > "$T/collive.json" <<'EOF'
{"items":[
 {"metadata":{"name":"c1","namespace":"b","resourceVersion":"5"},"spec":{"rules":[{"host":"sh"}]}},
 {"metadata":{"name":"c2","namespace":"b","resourceVersion":"6"},"spec":{"rules":[{"host":"sh"}]}}
]}
EOF
# someone else's Ingress already holding the name this migration would generate
cat > "$T/squat.json" <<'EOF'
{"apiVersion":"networking.k8s.io/v1","kind":"Ingress",
 "metadata":{"name":"mm-sh","namespace":"b","labels":{},"annotations":{}},
 "spec":{"rules":[{"host":"sh"}]}}
EOF
mkdir -p "$T/cbackups" "$T/cexports"
: > "$T/calls.txt"
LOG_DIR=$T/logs BACKUP_ROOT=$T/cbackups EXPORT_ROOT=$T/cexports STUB_DIR=$T PATH="$T/cbin:$PATH" \
  "$DIR/migrate.sh" --apply -n b < /dev/null > "$T/collide.txt" 2>&1
crc=$?
ok "squatted generated name aborts apply" '[ $crc -ne 0 ] && grep -q "\[CONFLICT\] generated name" "$T/collide.txt"'
ok "squat abort mutates nothing"          '[ ! -s "$T/calls.txt" ]'

# a preflight that cannot read the cluster must fail closed, not report the name as free
mkdir -p "$T/fbin"
cat > "$T/fbin/kubectl" <<'EOF'
#!/usr/bin/env bash
case $1 in
  get) if [[ " $* " == *" -l "* ]]; then exit 0; fi
       if [[ $3 == -* ]]; then cat "$STUB_DIR/collive.json"; exit 0; fi
       echo "Error from server (Forbidden): ingresses is forbidden" >&2; exit 1 ;;
  apply|patch|delete) echo "$*" >> "$STUB_DIR/calls.txt"; cat > /dev/null ;;
esac
EOF
chmod +x "$T/fbin/kubectl"
: > "$T/calls.txt"
LOG_DIR=$T/logs BACKUP_ROOT=$T/cbackups EXPORT_ROOT=$T/cexports STUB_DIR=$T PATH="$T/fbin:$PATH" \
  "$DIR/migrate.sh" --apply -n b < /dev/null > "$T/noread.txt" 2>&1
nrc=$?
ok "unreadable preflight aborts apply"  '[ $nrc -ne 0 ] && grep -q "\[UNKNOWN\] cannot check generated name" "$T/noread.txt"'
ok "unreadable preflight mutates nothing" '[ ! -s "$T/calls.txt" ]'
LOG_DIR=$T/logs STUB_DIR=$T PATH="$T/fbin:$PATH" "$DIR/migrate.sh" -n b > "$T/noread2.txt" 2>&1
ok "unreadable preflight is not reported OK" '! grep -q "no existing Ingress uses a generated name" "$T/noread2.txt" && grep -q "\[UNKNOWN\]" "$T/noread2.txt"'
ok "unreadable cluster is not called a conflict" '! grep -q "rename or delete the conflicting" "$T/noread.txt" && grep -q "see the \[CONFLICT\]/\[UNKNOWN\]" "$T/noread.txt"'

# a healthy read that warns on stderr must not corrupt the preflight: stderr is not JSON
mkdir -p "$T/wbin"
cat > "$T/wbin/kubectl" <<'EOF'
#!/usr/bin/env bash
case $1 in
  get)
    echo "Warning: v1 Ingress is deprecated" >&2
    if [[ " $* " == *" -l "* ]]; then exit 0; fi
    # "get ingress mm-sh -n b --ignore-not-found -o json" names a ref; the list fetch does not.
    if [[ " $* " == *" --ignore-not-found "* ]]; then
      echo '{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"mm-sh","namespace":"b","labels":{"migrate.nginx.org/generated":"true"}}}'
    else
      cat "$STUB_DIR/collive.json"
    fi
    exit 0 ;;
  apply|patch|delete) echo "$*" >> "$STUB_DIR/calls.txt"; cat > /dev/null ;;
esac
EOF
chmod +x "$T/wbin/kubectl"
LOG_DIR=$T/logs STUB_DIR=$T PATH="$T/wbin:$PATH" "$DIR/migrate.sh" -n b > "$T/warn.txt" 2>&1
ok "stderr warning does not break preflight" '! grep -q "parse error" "$T/warn.txt" && grep -q "\[OK\] no existing Ingress uses a generated name" "$T/warn.txt"'
ok "stderr warning raises no false conflict" '! grep -q "\[CONFLICT\]" "$T/warn.txt"'
: > "$T/calls.txt"
LOG_DIR=$T/logs BACKUP_ROOT=$T/cbackups EXPORT_ROOT=$T/cexports STUB_DIR=$T PATH="$T/wbin:$PATH" \
  "$DIR/migrate.sh" --apply -n b < /dev/null > "$T/warn2.txt" 2>&1 ; rc=$?
ok "stderr warning does not abort apply" '[ $rc -eq 0 ] && grep -q "Migration completed" "$T/warn2.txt"'

# server dry-run validation (stubbed kubectl)
: > "$T/vcalls.txt"
STUB_DIR=$T PATH="$T/kbin:$PATH" LOG_DIR=$T/logs BACKUP_ROOT=$T/backups EXPORT_ROOT=$T/exports \
  "$DIR/migrate.sh" -n a > "$T/v1.txt" 2>&1 ; rc=$?
ok "online dry-run validates" '[ $rc -eq 0 ] && grep -q "\[VALID\] a/app" "$T/v1.txt" && grep -q "Validation  VALID: 1  INVALID: 0" "$T/v1.txt"'
ok "validation uses --dry-run=server" 'grep -q -- "--dry-run=server" "$T/vcalls.txt"'
ok "validation payload has no resourceVersion" '! grep -q "resourceVersion" "$T/vcalls.txt"'
STUB_DIR=$T STUB_FAIL=app PATH="$T/kbin:$PATH" LOG_DIR=$T/logs BACKUP_ROOT=$T/backups EXPORT_ROOT=$T/exports \
  "$DIR/migrate.sh" -n a > "$T/v2.txt" 2>&1 ; rc=$?
ok "invalid validation still exits 0" '[ $rc -eq 0 ] && grep -q "\[INVALID\] a/app" "$T/v2.txt" && grep -q "INVALID: 1" "$T/v2.txt"'
STUB_DIR=$T PATH="$T/kbin:$PATH" LOG_DIR=$T/logs BACKUP_ROOT=$T/backups EXPORT_ROOT=$T/exports \
  "$DIR/migrate.sh" -n a --skip-validation > "$T/v3.txt" 2>&1 ; rc=$?
ok "--skip-validation skips validation" '[ $rc -eq 0 ] && grep -q "skipped (--skip-validation)" "$T/v3.txt" && ! grep -q "\[VALID\]" "$T/v3.txt"'

# generated masters/minions are validated too (host collision fixture)
mkdir -p "$T/v"
jq -c '{items: [.items[] | select(.metadata.name=="c1" or .metadata.name=="c2")]}' "$T/in.json" > "$T/v/live.json"
STUB_DIR=$T/v PATH="$T/kbin:$PATH" LOG_DIR=$T/logs BACKUP_ROOT=$T/backups EXPORT_ROOT=$T/exports \
  "$DIR/migrate.sh" -n b > "$T/v4.txt" 2>&1 ; rc=$?
ok "generated master is validated" '[ $rc -eq 0 ] && grep -q "\[VALID\] create b/mm-shared" "$T/v4.txt"'

# interactive confirmation needs a pty; `script` provides one
if command -v script >/dev/null; then
  : > "$T/calls.txt"
  echo yes | script -qec "STUB_DIR=$T PATH=$T/kbin:$PATH LOG_DIR=$T/logs BACKUP_ROOT=$T/backups2 EXPORT_ROOT=$T/exports2 '$DIR/migrate.sh' --apply" /dev/null > "$T/a3.txt" 2>&1
  ok "interactive 'yes' applies all namespaces" 'grep -q "Migration completed" "$T/a3.txt" && grep -q "patch ingress app -n a" "$T/calls.txt"'
  ok "interactive run exports YAML" '[ -s "$T"/exports2/migrate_export_*/a/app.yaml ]'
else
  echo "skip interactive pty test (script not installed)"
fi

[ $fail -eq 0 ] && echo "ALL PASSED" || { echo "SOME FAILED"; exit 1; }
