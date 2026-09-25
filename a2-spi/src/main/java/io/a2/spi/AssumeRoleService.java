package io.a2.spi;

import io.a2.spi.model.AssumeRoleRequest;
import io.a2.spi.model.TokenResult;

/**
 * Service for temporary credential issuance and role assumption / impersonation.
 */
public interface AssumeRoleService {

    /**
     * Assume a role and receive a short-lived token (default 1 hour).
     */
    TokenResult assumeRole(AssumeRoleRequest request);

    /**
     * Impersonate another principal.
     */
    TokenResult impersonate(String callerPrincipalId, String targetPrincipalId,
                            long durationSeconds, String reason);

    /**
     * Issue a temporary service-to-service credential.
     */
    TokenResult issueTemporaryCredential(String principalId, String audience,
                                         long durationSeconds, String... scopes);
}
