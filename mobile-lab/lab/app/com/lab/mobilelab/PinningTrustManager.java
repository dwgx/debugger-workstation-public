package com.lab.mobilelab;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import okhttp3.CertificatePinner;

/**
 * Pinning mechanism #2 of 3: a hand-rolled {@link javax.net.ssl.X509TrustManager}.
 *
 * This is the interesting one for static analysis because it has NO library marker. A tool
 * that only greps for "CertificatePinner" finds mechanism #1 and misses this entirely. The
 * tell is structural: the class implements X509TrustManager, and checkServerTrusted either
 * delegates to a pinner or compares the chain itself.
 *
 * Note what this class does NOT do: it does not disable verification, does not accept an
 * empty chain, and does not catch-and-swallow CertificateException. An all-trusting
 * trust manager is a finding; this is the correct, restrictive shape.
 */
public class PinningTrustManager implements javax.net.ssl.X509TrustManager {

    private final CertificatePinner pinner;
    private final String expectedHost;

    public PinningTrustManager(CertificatePinner pinner) {
        this.pinner = pinner;
        this.expectedHost = "telemetry.lab.invalid";
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("client certificates are not accepted by this app");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("empty server chain");
        }
        // Delegating to the pinner is the common correct shape.
        try {
            this.pinner.check(this.expectedHost, (Object[]) chain);
        } catch (CertificatePinner.SSLPeerUnverifiedException e) {
            throw new CertificateException("pin mismatch for " + this.expectedHost);
        }
    }

    /**
     * Returning null means "no client CA is configured", which is the documented OkHttp
     * idiom. It is NOT "trust everything" — the distinction matters, and the analyser
     * reports a null-returning getAcceptedIssuers differently from an empty-array one.
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}
