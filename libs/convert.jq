include "lib";

def P: "nginx.ingress.kubernetes.io/";
def clean: tostring | gsub("[“”‘’\"']"; "") | trim;
def bool: clean | ascii_downcase | . == "true";
def dur: if test("^[0-9]+$") then . + "s" else . end;
def durok: test("^[0-9]+(ms|s|m|h|d)?$");
def cidrok:
  if test(":") then
    test("^[0-9a-fA-F:]+(/[0-9]{1,3})?$")
    and ((split("/")[1] // "0") | tonumber <= 128)
  else test("^([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?$")
    and (split("/")[0] | split(".") | map(tonumber) | all(. <= 255))
    and ((split("/")[1] // "0") | tonumber <= 32)
  end;

def put($k; $n; $v):
  .set[$n] = $v
  | .logs += [{lvl: "MAP", key: $k, msg: "nginx.org/\($n) = \($v | tojson)"}];
def note($lvl; $k; $msg): .logs += [{lvl: $lvl, key: $k, msg: $msg}];
def blk($k; $msg): .block = true | note("BLOCK"; $k; $msg);
# For a community "true"/"false" annotation value: decode it, then emit the nginx.org form.
# $v | boolstr is for an already-decoded boolean; $v | bool | boolstr for a raw string.
def boolstr: if . then "True" else "False" end;

# Fold a parsed snippet ($r) into the accumulator, tagging its log lines with the source key
# so the report can say which community annotation each directive came from.
def absorb($k; $r):
  .loc += $r.loc | .srv += $r.srv | .ws = (.ws or $r.ws)
  | .pv = ($r.pv // .pv) | .vhost = ($r.vhost // .vhost)
  | .block = (.block or $r.block) | .logs += ($r.logs | map(. + {key: $k}));

# Only claim a conversion when the snippet produced something; a block is already reported.
def claim_loc($k; $r):
  if ($r.block | not) and ((($r.loc | length) + ($r.srv | length)) > 0 or $r.ws
                            or $r.pv != null or $r.vhost != null) then
    note("MAP"; $k; "converted into nginx.org/location-snippets")
  elif $r.block then .
  else note("INFO"; $k; "no directive survived conversion; nothing set") end;

def RENAME: {
  "proxy-next-upstream": "proxy-next-upstream",
  "proxy-next-upstream-tries": "proxy-next-upstream-tries",
  "proxy-buffer-size": "proxy-buffer-size",
  "proxy-busy-buffers-size": "proxy-busy-buffers-size",
  "proxy-max-temp-file-size": "proxy-max-temp-file-size",
  "client-body-buffer-size": "client-body-buffer-size",
  "proxy-redirect-from": "proxy-redirect-from",
  "proxy-redirect-to": "proxy-redirect-to",
  "ssl-ciphers": "ssl-ciphers",
  "app-root": "app-root",
  "websocket-services": "websocket-services",
  "ssl-services": "ssl-services",
  "grpc-services": "grpc-services",
  "proxy-body-size": "client-max-body-size"
};
def DURS: ["proxy-connect-timeout", "proxy-read-timeout", "proxy-send-timeout", "proxy-next-upstream-timeout"];
def HANDLED_LATER: [
  "ssl-redirect", "force-ssl-redirect", "upstream-hash-by", "load-balance", "backend-protocol",
  "rewrite-target", "use-regex", "whitelist-source-range", "denylist-source-range",
  "limit-rps", "limit-rpm", "limit-burst-multiplier", "affinity", "session-cookie-name",
  "session-cookie-expires", "session-cookie-max-age", "session-cookie-path",
  "permanent-redirect", "permanent-redirect-code", "temporal-redirect", "temporal-redirect-code",
  "proxy-buffers-number", "proxy-http-version", "upstream-vhost", "canary"
];
def BLOCKS: "^(auth-.*|enable-global-auth|satisfy|enable-modsecurity|enable-owasp-core-rules|modsecurity-.*|canary-.*|proxy-ssl-.*|ssl-passthrough|limit-connections)$";
def DROPS: {
  "add-headers": "ConfigMap-only key in ingress-nginx, never effective as an annotation; set response headers via configuration-snippet instead",
  "ssl-protocols": "no per-Ingress equivalent; set ssl-protocols in the F5 ConfigMap",
  "custom-headers": "no F5 OSS equivalent",
  "custom-http-errors": "ingress-nginx and F5 semantics differ; configure nginx.org/custom-http-errors manually",
  "default-backend": "no F5 equivalent; use spec.defaultBackend",
  "enable-cors": "no F5 OSS equivalent; add CORS headers in location-snippets manually",
  "server-alias": "no F5 equivalent; add extra hosts to spec.rules",
  "from-to-www-redirect": "no F5 equivalent",
  "mirror-request-body": "no F5 equivalent", "mirror-target": "no F5 equivalent", "mirror-host": "no F5 equivalent",
  "stream-snippet": "no F5 equivalent",
  "upstream-hash-by-subset": "no F5 equivalent", "upstream-hash-by-subset-size": "no F5 equivalent",
  "affinity-mode": "no F5 equivalent", "affinity-canary-behavior": "no F5 equivalent",
  "session-cookie-domain": "not verified on F5 OSS sticky-cookie-services", "session-cookie-samesite": "not verified on F5 OSS sticky-cookie-services",
  "session-cookie-secure": "not verified on F5 OSS sticky-cookie-services",
  "session-cookie-change-on-failure": "no F5 equivalent", "session-cookie-conditional-samesite-none": "no F5 equivalent",
  "limit-whitelist": "no F5 equivalent",
  "connection-proxy-header": "no F5 equivalent",
  "http2-push-preload": "no F5 equivalent",
  "preserve-trailing-slash": "no F5 equivalent",
  "enable-opentelemetry": "no F5 OSS equivalent", "opentelemetry-trust-incoming-span": "no F5 OSS equivalent",
  "x-forwarded-prefix-unused": ""
};

def step($k; $a):
  ($a[$k]) as $v
  | if (DURS | index($k)) then
      ($v | clean) as $d
      | if ($d | durok) then put($k; $k; ($d | dur))
        else blk($k; "value \($d | tojson) is not an nginx time; copying it through would break the generated config") end
    elif RENAME[$k] != null then put($k; RENAME[$k]; ($v | clean))
    elif $k == "proxy-buffering" then put($k; "proxy-buffering"; ($v | bool | boolstr))
    elif $k == "ssl-prefer-server-ciphers" then put($k; "ssl-prefer-server-ciphers"; ($v | bool | boolstr))
    elif $k == "service-upstream" then
      if ($v | bool) then put($k; "use-cluster-ip"; "True") else note("INFO"; $k; "false, nothing to do") end
    elif $k == "enable-access-log" then
      if ($v | bool) then note("INFO"; $k; "true is the default") else .loc += ["access_log off;"] | note("MAP"; $k; "location-snippets: access_log off;") end
    elif $k == "enable-rewrite-log" then
      if ($v | bool) then .loc += ["rewrite_log on;"] | note("MAP"; $k; "location-snippets: rewrite_log on;") else . end
    elif $k == "proxy-request-buffering" then
      ($v | clean | ascii_downcase) as $b
      | if ($b == "on" or $b == "off") then
          .loc += ["proxy_request_buffering \($b);"] | note("MAP"; $k; "location-snippets: proxy_request_buffering \($b);")
        else blk($k; "value \($b | tojson) is not on/off") end
    elif $k == "proxy-cookie-domain" then
      if ($v | clean | safe) then .loc += ["proxy_cookie_domain \($v | clean);"] | note("MAP"; $k; "location-snippets: proxy_cookie_domain")
      else blk($k; "value contains characters that would inject another directive") end
    elif $k == "proxy-cookie-path" then
      if ($v | clean | safe) then .loc += ["proxy_cookie_path \($v | clean);"] | note("MAP"; $k; "location-snippets: proxy_cookie_path")
      else blk($k; "value contains characters that would inject another directive") end
    elif $k == "x-forwarded-prefix" then
      # Quoted, so a trailing backslash would escape the closing quote and swallow the rest
      # of the line. Every sibling key that emits a snippet validates with `safe` first.
      if ($v | clean | safe) then
        .loc += ["proxy_set_header X-Forwarded-Prefix \"\($v | clean)\";"] | note("MAP"; $k; "location-snippets: proxy_set_header X-Forwarded-Prefix")
      else blk($k; "value contains characters that would inject another directive") end
    elif $k == "configuration-snippet" then
      ($v | snippet("loc")) as $r | absorb($k; $r) | claim_loc($k; $r)
    elif $k == "server-snippet" then
      ($v | snippet("srv")) as $r | absorb($k; $r)
      | note("MAP"; $k; "split: location-valid directives to location-snippets, others to server-snippets")
    elif $k == "canary" then
      if ($v | bool) then blk($k; "canary routing has no F5 OSS equivalent; dropping it would send all traffic to the stable backend") else note("INFO"; $k; "canary disabled") end
    elif ($k | test(BLOCKS)) then
      if ($k | test("^(enable-global-auth|enable-modsecurity|enable-owasp-core-rules|ssl-passthrough)$")) and ($v | bool | not) then note("INFO"; $k; "false, nothing to do")
      elif ($k | test("^canary-")) and (($a.canary // "false") | bool | not) then note("INFO"; $k; "canary disabled, ignored")
      else blk($k; "security/traffic control with no F5 OSS annotation equivalent (value: \($v | tojson))") end
    elif DROPS[$k] != null then note("DROP"; $k; DROPS[$k])
    elif (HANDLED_LATER | index($k)) then .
    else note("DROP"; $k; "unknown or unsupported on F5 OSS (value: \($v | tojson | .[0:80]))") end;

def dedupe: reduce .[] as $x ([]; if index([$x]) then . else . + [$x] end);

# ssl redirects. force-ssl-redirect wins over ssl-redirect; without spec.tls there is nothing
# to redirect to, so the fallback goes through redirect-to-https instead.
def ssl_redirect($c; $hasTls):
  if $c["force-ssl-redirect"] != null and ($c["force-ssl-redirect"] | bool) then
    if $hasTls then put("force-ssl-redirect"; "ssl-redirect"; "True") | put("force-ssl-redirect"; "http-redirect-code"; "308")
    else put("force-ssl-redirect"; "redirect-to-https"; "True") | note("WARN"; "force-ssl-redirect"; "no spec.tls: mapped to redirect-to-https, which trusts X-Forwarded-Proto from the load balancer")
    end
  elif $c["ssl-redirect"] != null then
    if ($c["ssl-redirect"] | bool) then
      if $hasTls then put("ssl-redirect"; "ssl-redirect"; "True") | put("ssl-redirect"; "http-redirect-code"; "308")
      else note("INFO"; "ssl-redirect"; "true but no spec.tls: community redirected nothing either") end
    else put("ssl-redirect"; "ssl-redirect"; "False") end
  else . end;

def load_balance($c):
  if $c["upstream-hash-by"] != null then
    ($c["upstream-hash-by"] | trim) as $h
    | if ($h | test("^[$A-Za-z0-9_.:/-]+( [$A-Za-z0-9_.:/-]+)*$")) then
        put("upstream-hash-by"; "lb-method"; "hash \($h) consistent")
        | (if $c["load-balance"] != null then note("INFO"; "load-balance"; "ignored: upstream-hash-by takes precedence") else . end)
      else note("DROP"; "upstream-hash-by"; "value has characters unsafe for an nginx directive") end
  elif $c["load-balance"] != null then
    ($c["load-balance"] | clean | ascii_downcase) as $lb
    | if (["round_robin","least_conn","ip_hash"] | index($lb)) then put("load-balance"; "lb-method"; $lb)
      else note("DROP"; "load-balance"; "\($lb) has no F5 OSS equivalent") end
  else . end;

def backend_protocol($c; $svcstr):
  if $c["backend-protocol"] != null then
    ($c["backend-protocol"] | clean | ascii_downcase) as $bp
    | if $svcstr == "" then note("WARN"; "backend-protocol"; "no backend services found, nothing mapped")
      elif $bp == "https" then put("backend-protocol"; "ssl-services"; $svcstr)
      elif $bp == "grpc" then put("backend-protocol"; "grpc-services"; $svcstr)
      elif $bp == "grpcs" then put("backend-protocol"; "grpc-services"; $svcstr) | put("backend-protocol"; "ssl-services"; $svcstr)
      elif $bp == "http" or $bp == "auto_http" then note("INFO"; "backend-protocol"; "\($bp) is the F5 default")
      else note("DROP"; "backend-protocol"; "\($bp) has no F5 OSS equivalent") end
  else . end;

def rewrite_regex($c):
  ($c["use-regex"] != null and ($c["use-regex"] | bool)) as $rx
  | ($c["rewrite-target"] | if . == null then null else clean end) as $rt
  | (if $rt != null then
       if ($rt | safe) then put("rewrite-target"; "rewrite-target"; $rt)
       else note("DROP"; "rewrite-target"; "value contains characters unsafe for an nginx directive") end
     else . end)
  | (if $rx or ($rt != null and ($rt | test("\\$[0-9]"))) then put("use-regex"; "path-regex"; "case_insensitive") else . end);

# An invalid CIDR in either list blocks: dropping a whitelist would open access.
def source_ranges($c):
  ([ ($c["whitelist-source-range"] // "") | tostring, ($c["denylist-source-range"] // "") | tostring ]
   | map(split(",") | map(gsub("\\s"; "")) | map(select(length > 0)))) as [$wl, $dl]
  | ([ $wl[], $dl[] ] | map(select(cidrok | not))) as $bad
  | if ($bad | length) > 0 then
      blk("whitelist-source-range"; "invalid CIDR(s) \($bad | join(", ")); dropping the list would open access")
    elif ($wl | length) + ($dl | length) > 0 then
      .acl = ([ $dl[] | "deny \(.);" ] + [ $wl[] | "allow \(.);" ] + (if ($wl | length) > 0 then ["deny all;"] else [] end))
      | note("MAP"; "whitelist-source-range"; "location-snippets: \(.acl | join(" "))")
    else . end;

def rate_limit($c):
  if $c["limit-rps"] != null or $c["limit-rpm"] != null then
    (if $c["limit-rps"] != null then {n: ($c["limit-rps"] | clean), u: "r/s", k: "limit-rps"} else {n: ($c["limit-rpm"] | clean), u: "r/m", k: "limit-rpm"} end) as $l
    | (($c["limit-burst-multiplier"] // "5") | clean) as $m
    | if ($l.n | test("^[1-9][0-9]*$")) and ($m | test("^[1-9][0-9]*$")) then
        put($l.k; "limit-req-rate"; "\($l.n)\($l.u)")
        | put($l.k; "limit-req-burst"; (($l.n | tonumber) * ($m | tonumber) | tostring))
        | put($l.k; "limit-req-no-delay"; "true")
        | put($l.k; "limit-req-reject-code"; "503")
        | (if $c["limit-rps"] != null and $c["limit-rpm"] != null then note("WARN"; "limit-rpm"; "both set, limit-rps used") else . end)
      else note("DROP"; $l.k; "non-integer value; rate limit lost") end
  else . end;

def sticky_session($c; $svcs; $svcstr):
  if $c["affinity"] == null then . else
    if ($c["affinity"] | clean | ascii_downcase) == "cookie" and $svcstr != "" then
      (($c["session-cookie-name"] // "INGRESSCOOKIE") | clean) as $cn
      | (($c["session-cookie-max-age"] // $c["session-cookie-expires"] // "") | clean) as $ex
      | (($c["session-cookie-path"] // "") | clean) as $pa
      | if ($cn | test("^[A-Za-z0-9_.-]+$")) and ($ex == "" or ($ex | test("^[0-9]+$"))) and ($pa == "" or ($pa | safe)) then
          put("affinity"; "sticky-cookie-services"; ([ $svcs[] | "serviceName=\(.) \($cn)" + (if $ex != "" then " expires=\($ex)s" else "" end) + (if $pa != "" then " path=\($pa)" else "" end) ] | join(";")))
          | note("WARN"; "affinity"; "sticky-cookie-services on F5 OSS needs NGINX 1.29.6+; verify with nginx -t")
        else note("DROP"; "affinity"; "cookie settings contain unsupported values") end
    else note("DROP"; "affinity"; "only affinity=cookie is convertible") end
  end;

def redirects($c):
  if $c["permanent-redirect"] != null or $c["temporal-redirect"] != null then
    (if $c["permanent-redirect"] != null then {u: ($c["permanent-redirect"] | clean), c: (($c["permanent-redirect-code"] // "301") | clean), k: "permanent-redirect"}
     else {u: ($c["temporal-redirect"] | clean), c: (($c["temporal-redirect-code"] // "302") | clean), k: "temporal-redirect"} end) as $r
    | if ($r.u | safe) and ($r.u | test("#") | not) and ($r.c | test("^30[1-8]$")) then
        .loc += ["return \($r.c) \($r.u);"] | note("MAP"; $r.k; "location-snippets: return \($r.c) \($r.u);")
      else note("DROP"; $r.k; "unsafe URL or invalid code") end
  else . end;

def proxy_buffers($c):
  if $c["proxy-buffers-number"] == null then . else
    ($c["proxy-buffers-number"] | clean) as $n
    | if ($n | test("^[1-9][0-9]*$")) then
        put("proxy-buffers-number"; "proxy-buffers"; "\($n) \(($c["proxy-buffer-size"] // "4k") | clean)")
      else note("DROP"; "proxy-buffers-number"; "non-integer value") end
  end;

# websocket support, http version and vhost all interact: websocket forces 1.1, so the
# explicit proxy-http-version is reported as unused rather than conflicting.
def transport($c; $svcstr):
  (if .ws and (.set["websocket-services"] == null) and $svcstr != "" then
     put("configuration-snippet"; "websocket-services"; $svcstr) else . end)
  | (($c["proxy-http-version"] | if . == null then null else clean end) // .pv) as $pv
  | (if $pv != null then
       if .set["websocket-services"] != null then note("INFO"; "proxy-http-version"; "websocket requires 1.1 on F5, not set")
       elif (["1.0","1.1"] | index($pv)) then put("proxy-http-version"; "proxy-http-version"; $pv)
       else note("DROP"; "proxy-http-version"; "\($pv) unsupported") end
     else . end)
  | (($c["upstream-vhost"] | if . == null then null else clean end) // .vhost) as $vh
  | (if $vh != null then
       if ($vh | test("^[A-Za-z0-9.-]+$")) then put("upstream-vhost"; "upstream-vhost"; $vh)
       else note("DROP"; "upstream-vhost"; "F5 accepts a literal hostname only, got \($vh)") end
     else . end);

# Every community key must appear in the report, even when it only feeds another key
# (denylist joins the ACL block, the codes ride along with their main key). A key with no
# line would otherwise be nulled in the patch with nothing said about it.
def report_leftovers($c):
  reduce ($c | keys[]) as $k (.;
    if (.logs | map(select(.key == $k)) | length) > 0 then .
    elif ($k | test("^session-cookie-")) and ($c.affinity == null) then
      note("DROP"; $k; "sticky settings need affinity=cookie, which is not set; dropped")
    elif ($k | test("^session-cookie-")) then note("INFO"; $k; "consumed by affinity=cookie")
    elif ($k | test("(^|-)redirect-code$")) then note("INFO"; $k; "consumed by its redirect annotation")
    elif ($k == "denylist-source-range") then note("INFO"; $k; "merged into the location-snippets ACL block")
    elif ($k == "limit-burst-multiplier") then note("INFO"; $k; "consumed by limit-rps/limit-rpm")
    else note("DROP"; $k; "no nginx.org equivalent produced; community key removed") end);

def convert:
  . as $ing
  | (.metadata.annotations // {}) as $all
  | ($all | with_entries(select(.key | startswith(P))) | with_entries(.key |= ltrimstr(P))) as $c
  | ([ .spec.rules[]?.http?.paths[]?.backend?.service?.name,
       .spec.defaultBackend?.service?.name ] | map(select(. != null)) | unique) as $svcs
  | ($svcs | join(",")) as $svcstr
  | ((.spec.tls // []) | length > 0) as $hasTls
  | { set: {}, loc: [], srv: [], logs: [], ws: false, pv: null, vhost: null, block: false } as $init
  | reduce ($c | keys[]) as $k ($init; step($k; $c))
  | ssl_redirect($c; $hasTls)
  | load_balance($c)
  | backend_protocol($c; $svcstr)
  | rewrite_regex($c)
  | source_ranges($c)
  | rate_limit($c)
  | sticky_session($c; $svcs; $svcstr)
  | redirects($c)
  | proxy_buffers($c)
  | transport($c; $svcstr)
  # ---- snippets
  | ((.acl // []) + .loc | dedupe) as $loc
  | (.srv | dedupe) as $srv
  | (if ($loc | length) > 0 then .set["location-snippets"] = ($loc | join("\n")) else . end)
  | (if ($srv | length) > 0 then .set["server-snippets"] = ($srv | join("\n")) else . end)
  | report_leftovers($c)
  # ---- overwrite warnings + patch
  | . as $S
  | ($all | with_entries(select(.key | startswith("nginx.org/")))) as $existing
  | { name: $ing.metadata.name, ns: $ing.metadata.namespace, rv: $ing.metadata.resourceVersion,
      block: $S.block,
      logs: ($S.logs + [ $S.set | to_entries[] | select($existing["nginx.org/\(.key)"] != null and $existing["nginx.org/\(.key)"] != .value)
                         | {lvl: "WARN", key: .key, msg: "overwrites existing nginx.org/\(.key)"} ]),
      set: $S.set,
      patch: ( ($c | keys | map({key: (P + .), value: null}) | from_entries)
               + ($S.set | with_entries(.key |= "nginx.org/" + .)) ) };
