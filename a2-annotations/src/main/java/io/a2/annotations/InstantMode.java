package io.a2.annotations;

/**
 * Modes for {@link A2InstantCredentials} — A2's unified short-lived credential issuance.
 * <p>
 * Maps cloud concepts without locking to one vendor:
 * <ul>
 *   <li>{@link #ASSUME_ROLE} — AWS STS–style elevated / session role</li>
 *   <li>{@link #IMPERSONATE} — GCP–style source principal → target principal</li>
 *   <li>{@link #SERVICE} — machine-to-machine / workload identity temp token</li>
 * </ul>
 * All modes hard-cap lifetime at 1 hour ({@code 3600} seconds).
 */
public enum InstantMode {

    /** Assume a role; effective identity becomes {@code role@assumed}. */
    ASSUME_ROLE,

    /**
     * Impersonate another principal.
     * Source = authenticated caller; target = {@code targetPrincipal}.
     */
    IMPERSONATE,

    /** Service-to-service temporary credential for an audience. */
    SERVICE
}
