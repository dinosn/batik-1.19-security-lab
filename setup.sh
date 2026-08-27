#!/usr/bin/env bash
# Batik 1.19 security lab — setup. Downloads the OFFICIAL Apache Batik 1.19 binary distribution,
# verifies its SHA-512, and compiles the shared harnesses. Idempotent.
#
# Source release SHA-512 (authenticated against the assessment):
#   batik-src-1.19.tar.gz : 95be1a33cf3231cf216206ea451ed5e8f8c37f812b3a6aedc1badf4d47a8c7bf84b6f118f35b44a29400d42db65ec2e699342cb62df3678fd4a1825aa29bfad9
# (This lab exercises the binary distribution; its own .sha512 is verified below.)
set -euo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$LAB"; cd "$LAB"
BASE="https://archive.apache.org/dist/xmlgraphics/batik/binaries"
TGZ="batik-bin-1.19.tar.gz"

echo "[*] workdir: $LAB"
if [ ! -f "$TGZ" ]; then
  echo "[*] downloading $TGZ"
  curl -fsSL -o "$TGZ" "$BASE/$TGZ"
fi
echo "[*] verifying SHA-512 against Apache archive"
EXPECT="$(curl -fsSL "$BASE/$TGZ.sha512" | awk '{print $1}')"
ACTUAL="$(sha512sum "$TGZ" | awk '{print $1}')"
if [ "$EXPECT" != "$ACTUAL" ]; then echo "[!] SHA-512 MISMATCH"; echo "  expect=$EXPECT"; echo "  actual=$ACTUAL"; exit 1; fi
echo "[+] SHA-512 OK: $ACTUAL"

[ -d batik-1.19 ] || tar xzf "$TGZ"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*")"
echo "[*] java: $(java -version 2>&1 | head -1)"
echo "[*] compiling shared harness"
cp "$HERE/harness/"*.java "$LAB/" 2>/dev/null || true
javac -cp "$CP" "$LAB"/BatikProbe.java
echo "[+] setup complete. Run the PoCs in poc/ (each is self-contained)."
echo "    e.g.  BATIK_LAB_DIR=$LAB bash $HERE/poc/f1-redirect-ssrf.sh"
