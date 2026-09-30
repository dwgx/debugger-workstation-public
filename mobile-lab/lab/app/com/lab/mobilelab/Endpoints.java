package com.lab.mobilelab;

/**
 * Hardcoded constants. This is the string/endpoint extraction target: every value here is a
 * PUBLIC FIXTURE in a self-authored lab, deliberately shaped like the real thing so the
 * extractor's classification rules are exercised (URL, key-shaped constant, host, path).
 *
 * None of these values is a real credential, host, or key. `api.lab.invalid` uses the
 * reserved `.invalid` TLD (RFC 2606) so it can never resolve.
 */
public final class Endpoints {

    private Endpoints() {}

    /** Production-style base URL. `.invalid` is reserved and never resolves. */
    public static final String API_BASE = "https://api.lab.invalid";

    public static final String PATH_SESSION = "/v2/session";
    public static final String PATH_ATTEST = "/v2/attest";

    /** Telemetry sink — a second host, so the extractor must report hosts, not just one URL. */
    public static final String TELEMETRY_HOST = "telemetry.lab.invalid";
    public static final String TELEMETRY_URL = "https://telemetry.lab.invalid/ingest";

    /**
     * Deliberately key-SHAPED so the extractor's "this looks like a credential" rule fires
     * and its redaction path is proven. The value is published in this repository and in
     * the APK; it authenticates nothing and is not a secret.
     */
    public static final String API_KEY_LIKE = "sk-lab-PLACEHOLDER-0000000000000000";

    /** Key material handed to the JNI KDF. Public fixture, not a secret. */
    public static final String SALT = "mobilelab-fixture-salt-v1";
}
