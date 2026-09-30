package com.lab.mobilelab;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

/**
 * Pinning mechanism #1 of 3: OkHttp {@link CertificatePinner}.
 *
 * Written the way a real app writes it, so the static pin extractor has something true to
 * find: a Builder, an add(host, pin) call with a real-looking sha256/ base64 digest, and a
 * client that consumes the built pinner.
 *
 * The digests are syntactically valid but are fixtures, not a real certificate's SPKI.
 * Publishing a pin for a certificate you own is the normal way to ship an app; this lab
 * pins a host that cannot resolve.
 */
public class ApiClient {

    private static final String PIN_HOST = "api.lab.invalid";

    /** sha256/ + base64 SPKI digest. The trailing "AA==" padding shape is what real pins have. */
    private static final String PIN_CURRENT = "sha256/7gL4Y5kKz6bWf0m2H1pQ8sT3vX7yZ0A9dC5eR1uI4oP2lM6nJ8fG0hK3w=";

    /** Backup pin for key rotation — a real app ships two so a rollover does not brick it. */
    private static final String PIN_BACKUP = "sha256/2pX7mK9qR4tY1uI3oP5aS8dF0gH6jK2lZ9xC4vB7nM1qW3eR5tY7uI9oP2aS4=";

    private final OkHttpClient client;
    private final CertificatePinner pinner;

    public ApiClient() {
        CertificatePinner.Builder builder = new CertificatePinner.Builder();
        builder.add(PIN_HOST, PIN_CURRENT);
        builder.add(PIN_HOST, PIN_BACKUP);
        this.pinner = builder.build();

        this.client = new OkHttpClient.Builder()
                .certificatePinner(this.pinner)
                .sslSocketFactory(null, new PinningTrustManager(this.pinner))
                .build();
    }

    /** The OkHttp path. Reached from MainActivity.onCreate. */
    public String fetchSession() {
        return Endpoints.API_BASE + Endpoints.PATH_SESSION;
    }

    public CertificatePinner getPinner() {
        return this.pinner;
    }

    public OkHttpClient getClient() {
        return this.client;
    }
}
