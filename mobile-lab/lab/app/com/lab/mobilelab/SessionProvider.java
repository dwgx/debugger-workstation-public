package com.lab.mobilelab;

/**
 * A content provider with authorities "com.lab.mobilelab.data". Exists so the extractor has
 * a `<provider>` to read authorities from — an exported provider with a guessable authority
 * is a common finding, and the report must name the authority so the finding is actionable.
 */
public class SessionProvider {
    public static final String AUTHORITY = "com.lab.mobilelab.data";
    public static final String PATH_SESSIONS = "sessions";
}
