package okhttp3;

/**
 * COMPILE-TIME STUB of the real okhttp3.CertificatePinner.
 *
 * Signature-compatible with OkHttp 4.x so the lab's own pinning code is written the way
 * a real app writes it. Not packaged: on a device the real OkHttp classes are present.
 */
public final class CertificatePinner {
    public static final class Builder {
        public Builder add(String domain, String pin) { return this; }
        public CertificatePinner build() { return new CertificatePinner(); }
    }

    public static final class Pin {
        public String pattern() { return ""; }
        public String toString() { return ""; }
    }

    public void check(String hostname, Object... peerCertificates) throws SSLPeerUnverifiedException {
    }

    public static final class SSLPeerUnverifiedException extends Exception {
        public SSLPeerUnverifiedException() { super(); }
    }
}
