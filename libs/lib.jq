def trim: sub("^\\s+"; "") | sub("\\s+$"; "");
def safe: test("^[^\\s;\"'{}\\\\]+$");
def unq:
  trim
  | if test("^\".*\"$"; "s") then .[1:-1] | gsub("\\\\\""; "\"")
    elif test("^'.*'$"; "s") then .[1:-1]
    else . end;
def esc: gsub("\""; "\\\"");
def words: [scan("\"(?:\\\\.|[^\"\\\\])*\"|'[^']*'|\\S+")];
def hdr: unq | first(capture("^(?<k>[^:]+):\\s*(?<v>.*)$"; "s")) // null;
def noflags:
  def f: if length == 0 then []
    elif (.[0] == "-s" or .[0] == "-t") then .[2:] | f
    else [.[0]] + (.[1:] | f) end;
  f;

# Headers the F5 template already sets to these values. A snippet line that repeats one is
# dropped as a no-op; a different value would be sent twice, so it is a WARN, not a mapping.
def F5H: {
  "host": "$host",
  "x-real-ip": "$remote_addr",
  "x-forwarded-for": "$proxy_add_x_forwarded_for",
  "x-forwarded-host": "$host",
  "x-forwarded-port": "$server_port",
  "x-forwarded-proto": "$scheme"
};

# Directives that enforce access control in a way F5 OSS has no annotation for. A snippet
# containing one is BLOCKed rather than converted: silently dropping it would open the route.
def AUTHRE: "(auth_request|auth_basic|auth_basic_user_file|satisfy|ssl_verify_client|ssl_client_certificate|modsecurity.*|.*_by_lua.*|js_access|js_content)";

# Result of converting one directive: the location snippets to add, plus notes for the report.
def res($loc; $logs): {loc: $loc, logs: $logs, ws: false, pv: null, vhost: null, block: false};
def line($lvl; $msg): {lvl: $lvl, msg: $msg};

# One nginx directive (no trailing ;) -> {loc, logs, ws, pv, vhost, block}
#
# more_set_headers and friends have no nginx.org equivalent, so each is rewritten into the
# plain directives that reproduce it: more_set_headers becomes proxy_hide_header + add_header
# (the hide prevents the upstream's copy from being sent as well).
def conv_dir:
  . as $d
  | ($d | capture("^(?<n>\\S+)\\s*(?<a>.*)$"; "s")) as $m
  | ($m.n | ascii_downcase) as $n
  | ($m.a | words) as $w
  | if $n == "more_set_headers" then
      ($w | noflags | map(hdr)) as $hs
      | ($w | map(select(. == "-s" or . == "-t")) | length > 0) as $filtered
      | res([ $hs[] | select(. != null) | (.k | trim) as $k
              | "proxy_hide_header \($k);",
                (if (.v | length) > 0 then "add_header \($k) \"\(.v | esc)\" always;" else empty end) ];
            [ (if $filtered then line("WARN"; "more_set_headers -s/-t status/type filter has no F5 OSS equivalent; header applied to all responses") else empty end),
              (if ($hs | map(select(. == null)) | length) > 0
               then line("WARN"; "more_set_headers argument without \"Key: Value\" form was dropped: \($d)") else empty end) ])
    elif $n == "more_clear_headers" then
      ($w | noflags | map(unq)) as $ks
      | res([ $ks[] | select(test("\\*") | not) | "proxy_hide_header \(.);" ];
            [ $ks[] | select(test("\\*")) | line("WARN"; "more_clear_headers wildcard \"\(.)\" has no F5 OSS equivalent; dropped") ])
    elif $n == "more_set_input_headers" then
      ($w | noflags | map(hdr)) as $hs
      | res([ $hs[] | select(. != null) | "proxy_set_header \(.k | trim) \"\(.v | esc)\";" ];
            (if ($hs | map(select(. == null)) | length) > 0 then [line("WARN"; "more_set_input_headers argument without \"Key: Value\" form was dropped: \($d)")] else [] end))
    elif $n == "more_clear_input_headers" then
      res([ $w | noflags | map(unq)[] | "proxy_set_header \(.) \"\";" ]; [])
    elif $n == "proxy_set_header" then
      ($w[0] // "" | unq) as $k
      | (($w[1:] | join(" ")) | unq) as $v
      | ($k | ascii_downcase) as $kl
      | if $kl == "upgrade" or ($kl == "connection" and ($v | test("upgrade|connection_upgrade|http_connection"; "i"))) then
          res([]; [line("INFO"; "\($k) header handled by nginx.org/websocket-services")]) | .ws = true
        elif F5H[$kl] != null then
          if $v == F5H[$kl] then
            res([]; [line("INFO"; "proxy_set_header \($k) \($v) dropped: identical to the F5 template default")])
          elif $kl == "host" and ($v != "") and ($v | test("\\$") | not) then
            res([]; [line("INFO"; "proxy_set_header Host \($v) mapped to nginx.org/upstream-vhost")]) | .vhost = $v
          else
            res([]; [line("WARN"; "proxy_set_header \($k) \($v) dropped: F5 template always sets \($k); a custom value would be sent twice. Re-implement with ConfigMap/upstream-vhost if needed")])
          end
        else res(["proxy_set_header \($k) \($w[1:] | join(" "));"]; []) end
    elif $n == "proxy_http_version" then
      res([]; []) | .pv = ($w[0] // null)
    elif ($n | test("^" + AUTHRE + "$")) then
      res([]; [line("BLOCK"; "snippet directive \"\($n)\" enforces access control that cannot be reproduced on F5 OSS")]) | .block = true
    else res(["\($d);"]; []) end;

def locok:
  test("^(keepalive_timeout|keepalive_requests|client_body_timeout|client_max_body_size|client_body_buffer_size|send_timeout|add_header|proxy_.*|allow|deny|gzip.*|access_log|rewrite|rewrite_log|return|set|more_.*|error_page|limit_.*|sendfile|tcp_nodelay|tcp_nopush|chunked_transfer_encoding|lingering_.*|resolver|resolver_timeout)$");

# Fold a converted directive's result into the running accumulator.
def merge($x):
  .loc += $x.loc | .srv += ($x.srv // []) | .logs += $x.logs
  | .ws = (.ws or $x.ws) | .pv = ($x.pv // .pv) | .vhost = ($x.vhost // .vhost)
  | .block = (.block or $x.block);

# Drop "#" comments without touching "#" inside quoted strings (nginx treats it as comment start).
def strip_comments:
  [scan("\"(?:\\\\.|[^\"\\\\])*\"|'[^']*'|#[^\n]*|[^#\"']+")]
  | map(select(startswith("#") | not)) | join("");

# $mode: "loc" = configuration-snippet, "srv" = server-snippet
def snippet($mode):
  (strip_comments | split("\n") | map(select(test("^\\s*$") | not)) | join("\n")) as $t
  | {loc: [], srv: [], logs: [], ws: false, pv: null, vhost: null, block: false} as $init
  | if ($t | test("[{}]")) then
      $init
      | (if $mode == "loc" then .loc = [$t | trim] else .srv = [$t | trim] end)
      | if ($t | test("(^|[\\s;{])" + AUTHRE + "([\\s;{]|$)"; "m")) then
          .block = true
          | .logs = [line("BLOCK"; "snippet contains a block with access-control directives; F5 OSS cannot reproduce them")]
        else
          .logs = [line("WARN"; "snippet contains nginx blocks; copied verbatim, any more_* / Lua directives inside need manual review")]
        end
    else
      [ $t | scan("(?:\"(?:\\\\.|[^\"\\\\])*\"|'[^']*'|[^;\"'])+") | trim | select(length > 0) ]
      | reduce .[] as $d ($init;
          ($d | capture("^(?<n>\\S+)"; "s").n | ascii_downcase) as $n
          | if $mode == "srv" and ($n | locok | not) then
              .srv += ["\($d);"]
              | .logs += [line("WARN"; "server-context directive \"\($n)\" kept in nginx.org/server-snippets; this OVERRIDES the ConfigMap server-snippets (error pages, /metrics deny) for this host")]
            else merge($d | conv_dir) end)
    end;
