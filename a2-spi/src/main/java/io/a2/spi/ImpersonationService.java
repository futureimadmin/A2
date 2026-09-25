package io.a2.spi;

import io.a2.spi.model.TokenResult;

import java.util.Set;

/**
 * Service for Assumed Role and User Impersonation.
 *
 * Typical flows:
 * - Service A assumes role "billing-admin" to call Service B (S2S).
 * - Support agent temporarily impersonates a customer (with audit).
 */
public interface ImpersonationService {

    /**
     * Assume a role. Returns short-lived credentials (default 1 hour).
     *
     * @param caller       the principal performing the assume
     * @param role         role name / ARN-style identifier
     * @param ttlSeconds   requested lifetime (capped at 3600 for S2S)
     * @param sessionName  optional session identifier for audit
     */
    TokenResult assumeRole(Principal caller, String role, long ttlSeconds, String sessionName);

    /**
     * Impersonate another principal (user). Requires explicit permission.
     *
     * @param caller           the admin / support principal
     * @param targetPrincipalId the user being impersonated
     * @param ttlSeconds       lifetime of the impersonation token
     * @param reason           mandatory audit reason
     */
    TokenResult impersonate(Principal caller, String targetPrincipalId, long ttlSeconds, String reason);

    /** Check whether the current context is an assumed-role or impersonation session. */
    boolean isAssumedOrImpersonated(SecurityContext ctx);

    /** Return the original (real) principal when under impersonation / assumed role. */
    Principal getOriginalPrincipal(SecurityContext ctx);
}
