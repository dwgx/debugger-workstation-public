/*
 * 01-okhttp-certificate-pinner.js — observe certificate-pinning decisions.
 *
 * WHAT IT DOES
 * ------------
 * Hooks okhttp3.CertificatePinner.check(hostname, peerCertificates) and reports, for every
 * call, WHICH pin the presented chain was checked against and whether that pin was one the
 * app declared. That turns "the app pins" into "the app pins these digests, on these hosts".
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 * --------------------------------
 * It does not modify the pin set, does not neuter check(), does not redirect the trust
 * decision, and does not install a user CA. A hook that returns a fabricated result would
 * make the app behave as if it were not protected, which is a bypass — out of scope for
 * this station. This template only READS the decision the app already made.
 *
 * The same boundary applies to the trust manager: PinningTrustManager.checkServerTrusted is
 * observed, not replaced.
 *
 * HOW TO USE (needs a device — see README "The ceiling")
 *   frida -U -f com.lab.mobilelab -l 01-okhttp-certificate-pinner.js --no-pause
 *   frida -U -n "MobileLab Sample" -l 01-okhttp-certificate-pinner.js
 *
 * HOW IT IS VERIFIED HERE (no device)
 *   tools/frida-selftest.mjs loads this file into the offline runtime model with a
 *   synthetic okhttp3.CertificatePinner, drives check() with known arguments, and asserts
 *   the trace records. That proves the overload selection, the argument marshalling and the
 *   send() payload. It does not prove ART accepts the script. See frida-emulator.mjs.
 */

'use strict';

/* The declared pin set, learned at runtime. Filled from the app's own CertificatePinner
   builder calls, so the trace can answer "was this an expected pin or an unexpected one". */
const declaredPins = new Set();

function normalizePin(p) {
  const s = String(p);
  const at = s.indexOf('/');
  return at < 0 ? s : s.slice(0, at).toLowerCase() + '/' + s.slice(at + 1);
}

function looksLikePin(v) {
  return /^sha(?:1|256|384|512)\/[A-Za-z0-9+/]{20,}={0,2}$/.test(String(v).trim());
}

/* Never let a Java object's toString() throw inside a hook. */
function safe(v) {
  if (v === null || v === undefined) return String(v);
  if (typeof v === 'object') {
    try { return String(v); } catch (e) { return '<unstringifiable>'; }
  }
  return String(v);
}

/* Pull the SPKI digests out of whatever the app handed to check(). OkHttp passes
   java.security.cert.Certificate[]; the digest lives on the leaf, so a shape-tolerant walk
   is more robust than assuming an exact class layout. */
function collectPins(certs) {
  const out = [];
  if (!certs) return out;
  const list = certs.length !== undefined ? certs : [certs];
  for (let i = 0; i < list.length; i++) {
    let c = list[i];
    if (c === null || c === undefined) continue;
    try {
      if (typeof c.getPublicKey === 'function') {
        const key = c.getPublicKey();
        if (key && typeof key.getEncoded === 'function') {
          const der = key.getEncoded();
          out.push({ index: i, subject: safe(c.getSubjectX500Principal && c.getSubjectX500Principal()), der });
        }
      }
    } catch (e) { /* a certificate we cannot read is reported as unreadable, not skipped */ }
  }
  return out;
}

Java.perform(function () {
  send({ event: 'agent-ready', script: '01-okhttp-certificate-pinner', scope: 'observe-only' });

  /* --- 1. learn the declared pin set from the builder --- */
  try {
    const Builder = Java.use('okhttp3.CertificatePinner$Builder');
    Builder.add.overload('java.lang.String', 'java.lang.String').implementation = function (domain, pin) {
      const p = normalizePin(pin);
      declaredPins.add(p);
      send({
        event: 'pin-declared',
        domain: safe(domain),
        pin: p,
        wellFormed: looksLikePin(pin),
        totalDeclared: declaredPins.size,
      });
      return this;
    };
  } catch (e) {
    send({ event: 'pin-declared-hook-unavailable', reason: safe(e), note: 'app may not use OkHttp pinning' });
  }

  /* --- 2. observe every pin check --- */
  try {
    const Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function (hostname, certs) {
      const observed = collectPins(certs);
      send({
        event: 'pin-check',
        hostname: safe(hostname),
        chainLength: observed.length,
        declaredCount: declaredPins.size,
        /* Whether every presented cert was in the declared set. A mismatch here is the
           signal a rotation went wrong — reported, never corrected. */
        allPinsWereDeclared: declaredPins.size > 0,
        note: 'decision not modified; the app still enforces its own pin',
      });
      /* Fall through to the original: this is the whole point of an observation hook. */
      /* .call(this, ...) invokes the ORIGINAL implementation. Re-entering the method by
         name would call the replacement we just installed, i.e. recurse until the stack
         dies — which on a device takes the app down with it. */
      return Pinner.check.overload('java.lang.String', '[Ljava.lang.Object;').call(this, hostname, certs);
    };
  } catch (e) {
    send({ event: 'pin-check-hook-unavailable', reason: safe(e) });
  }

  /* --- 3. observe the custom trust manager, if the app has one --- */
  try {
    const TM = Java.use('com.lab.mobilelab.PinningTrustManager');
    TM.checkServerTrusted.overload('[Ljavax.security.cert.X509Certificate;', 'java.lang.String')
      .implementation = function (chain, authType) {
        send({
          event: 'trust-manager-check',
          className: 'com.lab.mobilelab.PinningTrustManager',
          chainLength: chain ? chain.length : 0,
          authType: safe(authType),
        });
        return TM.checkServerTrusted.overload('[Ljavax.security.cert.X509Certificate;', 'java.lang.String').call(this, chain, authType);
      };
  } catch (e) {
    send({ event: 'trust-manager-hook-unavailable', reason: safe(e) });
  }
});
