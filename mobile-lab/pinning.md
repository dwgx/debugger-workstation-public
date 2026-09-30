# Certificate pinning — how to find it statically

A method, not a bypass. Everything here answers **"does this app pin, how, and against
what"**. Nothing here removes a pin, installs a user CA, or makes an app's verification
pass. If you need one of those on a third-party app, that is a test-authorization question,
not a tooling question.

The sample APK in `lab/app/` deliberately implements all four mechanisms below, so every
rule here is checked against a target whose source is in this repository.

## Why one grep is not enough

The interesting finding is usually **not** "the app uses `CertificatePinner`". It is "this
app pins in four independent places, so removing one changes nothing". Each mechanism lives
in a different layer, and a pass that only looks at one of them reports a partial picture
that reads as a complete one.

| # | Mechanism | Where it lives | What a DEX-only pass sees |
|---|---|---|---|
| 1 | `network_security_config.xml` | `res/xml/`, compiled AXML | **nothing** — no DEX string mentions it |
| 2 | OkHttp `CertificatePinner` | `okhttp3.CertificatePinner$Builder.add` | the class name and the digests |
| 3 | Custom `X509TrustManager` | any `implements X509TrustManager` | only if you look for the *interface* |
| 4 | Native pin table | `lib/<abi>/*.so` `.rodata` | **nothing** — the digests are not in the DEX |

## 1. Declarative: `network_security_config.xml`

**Find it:** the manifest's `application/@android:networkSecurityConfig`, and any
`res/xml/network_security_config.xml` in the APK.

**Read it:** `<pin-set><pin digest="sha256/…"/></pin-set>` is the pinning. Also note
`<base-config cleartextTrafficPermitted="true">` — that is a finding on its own.

**The trap that costs an hour:** `res/xml/*.xml` inside an APK is **compiled binary AXML**,
not the text that went in. Grepping the bytes for `<pin digest="` finds nothing and you
report "no declarative pinning" on an app that pins heavily. Parse it as AXML:

```
$ python -c "import zipfile;d=zipfile.ZipFile('app.apk').read('res/xml/network_security_config.xml');print(d[:4].hex())"
03000800        <- 0x00080003 little-endian = AXML chunk type
```

`(tools/analyze.mjs: parseAxml`) reads `<domain>` text from the `RES_XML_TEXT` chunk — the
host name is element *content*, not an attribute.

## 2. OkHttp `CertificatePinner`

**Find it:** `Java.use("okhttp3.CertificatePinner$Builder")`, then hook
`add(String domain, String pin)`. Every call is one declared pin, and the **first argument
is the host it applies to** — which is the fact that makes a pin list actionable.

**Also find it statically:** look for the class in the DEX method table, and for
`sha256/`-prefixed string literals. A pin literal in the DEX is a strong signal.

**Reporting note:** record host *and* digest together. "The app has 2 pins" is much less
useful than "the app pins api.example.com to these two SPKI digests, and ships no backup".

## 3. A hand-rolled `X509TrustManager`

This is the one a library-grep misses. There is no marker; the tell is structural:

- the class appears in the DEX **class** table as `...TrustManager` or implements
  `X509TrustManager`
- `checkServerTrusted` either delegates to a pinner or compares the chain itself

**The distinction that matters, and that tools routinely get wrong:**

| `getAcceptedIssuers()` returns | What it means |
|---|---|
| `null` | "no client CA configured" — the documented OkHttp idiom. **Not** a weakness. |
| `new X509Certificate[0]` | no CAs either; a configuration smell, not a bypass |
| a populated array | client-certificate auth is configured |

None of these disables *server* verification. The genuinely dangerous shapes are:
`checkServerTrusted` that returns without throwing, an empty `catch (CertificateException)`,
or a hostname check that is commented out. Report those specifically.

`lab/app/PinningTrustManager.java` is the **correct** restrictive shape — it delegates to the
pinner, rejects an empty chain, and never swallows a `CertificateException`. It is in the
sample so the analyser can be scored on a non-finding as well as a finding.

## 4. Native pinning

**Find it:** `lib/<abi>/*.so` → `.rodata` → `sha256/`-prefixed strings. The DEX usually holds
only a *table id*; the digests are in native memory, so this mechanism is invisible to a
DEX-only pass by construction.

Pair it with a JNI edge: if a Java `native` method takes a table id and a leaf certificate,
the comparison happens in C. `tools/analyze.mjs` resolves `Java_*` exports back to Java
class and method names by the JNI mangling rule, which is what lets it say *which* Java
call site leads to the native pin table.

**Caveat:** a native pin can be computed rather than stored — derived from the certificate at
runtime, or assembled from fragments. Absence of `sha256/` in `.rodata` is **not** evidence
of absence.

## The JNI naming rule

You need it to connect the two layers, and getting it wrong silently produces a report with
zero boundaries.

```
Java_ + <package with '.'→'/' and '_'→'_1', ';'→'_2', '['→'_3'> + '_' + <method, same escapes>
        + optional '__' + <JVM signature>
```

Order matters: escape `_` **first**, or every later replacement re-escapes the underscores
just introduced. `a_b;c[d` → `a_1b_2c_3d`, not `a_11b_2c_31d`.

Overloaded natives carry the signature suffix: `nativeReadFlag(int)` is
`Java_..._nativeReadFlag__I`. A library that binds with `RegisterNatives` has **no** `Java_`
exports at all — the boundary is not in the ELF. Report that as its own finding rather than
as "no natives found".

## Reporting shape

For each mechanism, report **where**, **what is pinned**, and **how confident you are**:

```jsonc
{ "kind": "okhttp-certificate-pinner",
  "where": "okhttp3.CertificatePinner$Builder.add",
  "domains": ["api.example.com"],
  "pins": 2,
  "confidence": "OBSERVED" }      // or INFERRED for the RegisterNatives case
```

And state the limit that matters: *these are the pins this APK declares statically. A pin
computed at runtime, fetched from a server, or enforced in code this pass cannot read is not
in this list.* Absence of evidence is not evidence of absence, and a report that blurs the
two is worse than one that says "not found".

## What this lab does not do

- it does not modify a pin set, return a fabricated `check()` result, or install a user CA
- it does not repack, re-sign, or redirect a third-party app
- `frida/hooks/01-okhttp-certificate-pinner.js` observes and calls through with
  `.call(this, …)`; the app's own verification still runs and still decides

Observing a pin decision is authorized instrumentation. Defeating one is not, and the line
does not move because a technique is interesting.
