package io.a2.annotations;

/**
 * Token kinds managed by A2.
 */
public enum TokenType {
    ACCESS,
    REFRESH,
    ID,
    API_KEY,
    SESSION,
    /** Short-lived service-to-service credential (default TTL 1h). */
    TEMPORARY,
    /** Credential obtained via AssumeRole. */
    ASSUMED_ROLE,
    /** Credential obtained via Impersonation. */
    IMPERSONATION,
    CUSTOM
}
