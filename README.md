# Apache Batik 1.19 — Security Research Lab

Reproducible proof-of-concept lab for external-resource / scripting security issues in **Apache Batik 1.19**
(latest release, 2025-05-06). Every finding below has a self-contained, runnable PoC under `poc/`.

- **Target:** Apache Batik 1.19 — `org.apache.xmlgraphics`. Official source release
  `batik-src-1.19.tar.gz`, SHA-512 `95be1a33…29bfad9` (verified against the Apache archive).
  The lab exercises the matching **binary** distribution (`batik-bin-1.19.tar.gz`), whose own `.sha512`
  is verified by `setup.sh`.
- **Status:** unpatched at time of writing; **private** research repo. Coordinated disclosure to
  Apache XML Graphics pending. Do not run against systems you do not own.
- **Environment used:** Linux + OpenJDK 21, Batik 1.19 binary dist (bundles Rhino 1.7.7).

> **Authorization / ethics.** This lab targets a local copy of open-source software for defensive
> research and coordinated disclosure. All PoCs run entirely against `127.0.0.1` loopback services in
> a throwaway `/tmp/batik-lab` workdir.

---

## Threat models

- **(A) Server-side untrusted-SVG processing** *(primary)* — an application transcodes attacker-supplied
  SVG (string / stream / `file:` URI) via `PNGTranscoder`/`JPEGTranscoder`/etc. Default `UserAgentAdapter`
  → `DefaultExternalResourceSecurity` (**same-host**) and `DefaultScriptSecurity` (**same-host**, Java
  scripts denied). External-entity XXE is hardened. Findings here defeat or side-step the same-host policy.
- **(B) Interactive / desktop viewing** — a user opens untrusted SVG in the Squiggle browser or an app
  embedding `JSVGCanvas`/`JSVGComponent`. Here the resource policy defaults to **Relaxed** (F-5), and the
  standard `SVGUserAgentAdapter` relaxes scripts too (enabling F-3/F-8).

---

## Findings

Severity is **likelihood × impact**, rated conservatively. "High only with internal reach" means the
network/filesystem the renderer can reach determines whether a Medium becomes High. This table reflects a
second independent review (severity de-inflated from the first pass; see *Review & corrections*).

| ID | Finding | Class | Severity | Reachability | PoC |
|----|---------|-------|----------|--------------|-----|
| **F-1** | HTTP-redirect bypass of the same-host policy (`ParsedURLData` follows redirects, no re-check) | SSRF | **Medium** (High w/ internal reach) | default transcoder; needs an HTTP doc URI + attacker same-host redirect | `poc/f1-redirect-ssrf.sh` |
| **F-2** | `xml:base`-forged origin in `SVGColorProfileElementBridge` (uses `getBaseURI()` as the check's doc URL) | SSRF (blind) | **Medium** (High deployment-dependent) | default transcoder; via `icc-color`; works with null doc URL | `poc/f2-xmlbase-ssrf.sh` |
| **F-3** | `window.getURL`/`postURL` do network/file I/O with **no** resource-security check | LFI + SSRF + exfil | **High** (for scripting-enabled embeddings) | interactive viewer + scripting enabled | `poc/f3-geturl-exfil.sh` |
| **F-4** | Origin checks compare **host only** (scheme + port ignored) | Hardening | **Informational** | — (amplifies F-1/F-2) | — |
| **F-5** | `JSVGCanvas`/`JSVGComponent`/Squiggle default to **Relaxed** external-resource loading (any host/scheme) | Insecure default → SSRF / file-open | **Medium** hardening (High in server-side embedding) | bare `new JSVGCanvas()`, Squiggle (default) | `poc/f5-relaxed-canvas.sh` |
| **F-6** | Null-host coalescing (`null != null` = false) lets a `file:` document open any local `file:` resource | LFI (constrained) | **Medium**, conditional | default transcoder; upload-transcode by `file:` URI | `poc/f6-nullhost-lfi.sh` |
| **F-7** | Unescaped TrueType `font-family`/`glyph-name` written into generated SVG | Injection / stored XSS | **Medium** (static, deployment-dependent) | ttf2svg / svggen font→SVG + output served | *(static; `svggen/font/SVGFont.java:246,451`)* |
| **F-8** | `application/java-archive` `<script>` → `DocumentJarClassLoader` runs an attacker JAR's `ScriptHandler` | Code execution | **High** (Critical only if auto-processed) | **not** default; RelaxedScriptSecurity (`SVGUserAgentAdapter` / Squiggle-ANY) | `poc/f8-java-archive-rce.sh` |
| **F-9** | `<tref>` renders external referenced **text** into the output (non-blind) | Disclosure amplifier | **Medium** (constrained to SVG targets) | default transcoder; amplifies F-1/F-6 | `poc/f9-tref-disclosure.sh` |

### The unifying weakness
Batik's external-resource **origin enforcement** is either **bypassable** (F-1 redirect, F-2 `xml:base`,
F-6 null-host) or **wide-open by default** in the Swing/browser stack (F-5). `<tref>` (F-9) and
`window.getURL` (F-3) make the disclosure **non-blind**. The same `SVGUserAgentAdapter` "relax everything"
default that opens resources (F-5) also opens scripts → the java-archive code-execution path (F-8). These
are the same class the vendor has been patching since 2022 (CVE-2022-38398/38648/42890/44729/44730).

### Verified sound (no issue)
- **External-entity XXE / DTD** — hardened, fail-closed in `SAXDocumentFactory` (both parser paths).
- **Rhino / ECMAScript RCE** — `RhinoClassShutter` denies all Java classes to scripts (empty whitelist),
  installed on every Rhino context; no escape found. *(F-8 is a different, non-Rhino path.)*
- **`jar:http:`** SSRF — blocked by the inner-host reparse. **ParsedURL userinfo** (`user@host`) — not confusable.

### Out of scope
~20 denial-of-service candidates (image-size, WMF/PNG allocation, billion-laughs internal entities,
`@import`/value-parser recursion, decompression bombs) were identified but are **excluded** per the
engagement's no-DoS scope.

---

## Setup

```bash
bash setup.sh                     # downloads batik-bin-1.19, verifies SHA-512, compiles the harness
# then run any PoC (each is self-contained; uses only 127.0.0.1 services):
BATIK_LAB_DIR=/tmp/batik-lab bash poc/f1-redirect-ssrf.sh
BATIK_LAB_DIR=/tmp/batik-lab bash poc/f2-xmlbase-ssrf.sh
BATIK_LAB_DIR=/tmp/batik-lab bash poc/f3-geturl-exfil.sh
BATIK_LAB_DIR=/tmp/batik-lab bash poc/f5-relaxed-canvas.sh
BATIK_LAB_DIR=/tmp/batik-lab bash poc/f6-nullhost-lfi.sh
BATIK_LAB_DIR=/tmp/batik-lab bash poc/f8-java-archive-rce.sh
BATIK_LAB_DIR=/tmp/batik-lab bash poc/f9-tref-disclosure.sh
```

Each PoC prints an `EXPECT:` line describing the pass condition. `evidence/` preserves the raw
research harnesses exactly as first run (unedited), for audit.

---

## Per-finding detail

### F-1 — SSRF via redirect bypass
`ParsedURLData.openStreamInternal` (`batik-util/.../ParsedURLData.java:522`) does `url.openConnection()`
and never `setInstanceFollowRedirects(false)`. The origin check runs on the pre-redirect URL; the
post-redirect URL (`postConnectionURL`, `:550`) is captured but never re-checked. A same-host `<image>`
that 302-redirects to a different host is fetched. **Fix:** disable redirect following, or re-check the
post-redirect URL. *Upheld by two independent reviewers (Codex + second opinion).*

### F-2 — SSRF via `xml:base` forge in the color-profile bridge
`SVGColorProfileElementBridge` (`:108-123`) builds the security-check *document* URL from
`profile.getBaseURI()` — attacker-controllable via `xml:base` — so the attacker controls both sides of the
same-host comparison. Reached via `icc-color`; works with a null document URL (raw-string transcode).
Response is consumed as an ICC profile → **blind** SSRF (internal host/port oracle). Only `<color-profile>`
does this; `<image>`/`<use>`/gradient use the true `getURL()`. **Fix:** use `svgDoc.getURL()`.

### F-3 — ungated `window.getURL`/`postURL`
`ScriptingEnvironment.Window.getURL/postURL` (`:1071-1247`) do `openStream()`/`openConnection()` with **no**
`checkLoadExternalResource`. The PoC uses a **restricted** scripting sandbox (Batik DOM/CSS + `java.lang.System`,
**not** `Runtime`/reflection): a direct `Runtime.exec` is blocked, yet `getURL` still reads a local file and
`postURL` exfiltrates it — proving it is a genuine resource-gate bypass, not an artifact of an
already-compromised environment. Reachable in an interactive viewer with scripting enabled. **Fix:** gate
`getURL`/`postURL` through `checkLoadExternalResource`.

### F-4 — host-only comparison *(hardening)*
`DefaultExternalResourceSecurity`/`DefaultScriptSecurity` compare `getHost()` only — scheme and port are
ignored. The class implements a documented "same server" policy, not browser-style origin isolation.
Informational; amplifies F-1/F-2. **Fix:** compare full origin.

### F-5 — Relaxed default in the Swing / browser stack *(insecure default)*
`JSVGComponent.BridgeUserAgent.getExternalResourceSecurity` (`:3604`) returns
`RelaxedExternalResourceSecurity` (empty check) when no `SVGUserAgent` is supplied — and `new JSVGCanvas()`
supplies none. Squiggle defaults `ALLOWED_EXTERNAL_RESOURCE_ORIGIN=ANY`; `SVGUserAgentAdapter` hardcodes
Relaxed. This is an unsafe **default / embedding footgun** (Relaxed is documented to load from anywhere),
**less** restrictive than the transcoder. Impact: blind SSRF + local file **open/parse** of Batik-parseable
resources (not arbitrary plaintext — Batik decodes, it does not echo). **Fix:** default a null-UA
`JSVGComponent` to `DefaultExternalResourceSecurity`/`NoLoad`; Squiggle default `DOCUMENT`/`NONE`.

### F-6 — `file:`-document local file read
`DefaultExternalResourceSecurity` (`:98`): with a host-less document URL (any `file:` URI) and a host-less
`file:` resource, `(docHost != externalResourceHost)` is `null != null` = false → unconditional allow. A
server transcoding an uploaded SVG by its `file:` URI can open arbitrary local files. Disclosure is
**constrained** to Batik-parseable content (images/SVG); `/etc/hostname` is opened/read but not echoed;
`file:`→`http` is correctly blocked. **Fix:** treat a null document host as fail-closed.

### F-7 — TTF→SVG injection *(static)*
`svggen/font/SVGFont.java:246,451` append `fontFamily`/`glyphName` (attacker TrueType strings) raw into
`font-family`/`glyph-name` attributes, bypassing the module's own escaper → markup injection into the
generated SVG. Requires the untrusted-font→SVG conversion use case + serving/rendering the output.
**Fix:** route those strings through the attribute escaper.

### F-8 — Java-archive `<script>` code execution
`BaseScriptingEnvironment.loadScript` (`:390-436`), for `<script type="application/java-archive">`, loads
the attacker JAR via `DocumentJarClassLoader`, reads its manifest `Script-Handler` class, and reflectively
runs it. **This is a documented feature and is DENIED by the default policy** (`DefaultScriptSecurity:81`),
so a bare `new JSVGCanvas()` and default Squiggle are safe. It is reachable only under
`RelaxedScriptSecurity` — the standard `SVGUserAgentAdapter`/`SVGUserAgentGUIAdapter`, or Squiggle with
script-origin `ANY`. `DocumentJarClassLoader` assigns permissions but enforces nothing without an active
`SecurityManager` (deprecated JDK 17, disabled by default JDK 24 / JEP 486; embedders rarely install one),
so the payload runs with the JVM's privileges. The PoC's `uid=0(root)` reflects the container's process
identity, **not** a Batik privilege escalation. **Severity:** High for a downstream product that renders
untrusted SVG with a relaxed Java-script policy; Critical only where such a service auto-processes attacker
SVG without interaction. **Fix:** deny `application/java-archive` for untrusted content; don't ship
`SVGUserAgentAdapter`'s relaxed policy unchanged; never treat `DocumentJarClassLoader` permissions as a
modern sandbox.

### F-9 — `<tref>` non-blind disclosure *(amplifier)*
`SVGTextElementBridge` tref handling (`:958-975`) renders the referenced element's text into the output —
so, combined with F-6/F-1, disclosure becomes **non-blind**. **Constraint:** external `tref` targets must
parse as an **SVG document** (SVG root); ordinary XML/config/SOAP/WSDL roots are rejected. So this discloses
external *SVG* text (other users' uploaded SVGs, an internal SVG endpoint), not arbitrary XML. Amplifier of
F-1/F-6, not a broad standalone class.

---

## Review & corrections (transparency)

This lab reflects **two** independent cross-vendor reviews of an initial assessment. The first pass
over-rated severity and mis-scoped three items; corrections adopted here:

- **F-3** — the first proof whitelisted `.*` (exposing all Java classes = already full RCE), so it proved
  nothing. Re-tested with a **restricted** whitelist (this repo's `poc/f3-geturl-exfil.sh`): `getURL` still
  exfiltrates while `Runtime` is blocked → finding holds.
- **F-8** — reclassified from "default Critical RCE" to **config-gated** (RelaxedScriptSecurity only; the
  default denies it). Java-archive scripting is a documented feature.
- **F-9** — narrowed from "arbitrary XML disclosure" to **SVG-document text** disclosure (non-SVG roots are
  rejected); reframed as an amplifier of F-1/F-6.
- **CSS `@import` redirect** — dropped as a distinct live finding: the tested redirect stayed on the same
  host (only the port changed), so it did not cross an origin boundary. It is a static variant of F-1.
- **Severity** — F-1/F-2/F-5/F-6 rated **Medium baseline** (High only with demonstrated internal reach /
  returned output), not blanket High.
- **`SecurityManager`** — corrected: deprecated for removal in JDK 17, disabled by default in JDK 24
  (JEP 486); on JDK 21 it is installable-with-warning. In practice embedders don't install one, so
  `DocumentJarClassLoader`'s Policy sandbox is inert.

Net defensible disposition: **F-1 and F-2** are the two strongest standalone candidates; **F-3** is a real
resource-gate bypass in scripting-enabled embeddings; **F-8** is real code execution under an opted-in
relaxed policy (not a default Batik RCE); **F-5/F-6/F-9** are real conditional / insecure-default behaviors;
**F-7** is a conditional static injection; **F-4** is hardening.

---

## Remediation summary

| ID | Fix |
|----|-----|
| F-1 | Disable redirect following, or re-check the post-redirect URL against the resource-security policy. |
| F-2 | Use the true `svgDoc.getURL()`/`getURLObject()` as the security-check doc URL (as `<image>` does). |
| F-3 | Route `window.getURL`/`postURL` through `checkLoadExternalResource`. |
| F-4 | Compare full origin (scheme+host+port), not host alone. |
| F-5 | Default null-UA `JSVGComponent` to `DefaultExternalResourceSecurity`/`NoLoad`; Squiggle default `DOCUMENT`/`NONE`. |
| F-6 | Treat a null document host as fail-closed (no `null==null` "same origin"). |
| F-7 | Escape `fontFamily`/`glyphName` (and all attacker-derived strings) via the attribute encoder. |
| F-8 | Deny `application/java-archive` for untrusted content; fix `SVGUserAgentAdapter`'s relaxed default. |
| F-9 | Bind the `<tref>` external-resolution to the same fail-closed origin policy as other resources. |
