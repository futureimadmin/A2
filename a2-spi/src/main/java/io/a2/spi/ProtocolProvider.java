package io.a2.spi;

import io.a2.annotations.Protocol;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

/**
 * Core SPI that every identity protocol must implement.
 * This is the extension point that makes A2 protocol-agnostic.
 */
public interface ProtocolProvider {

    /** Unique protocol identifier. */
    Protocol id();

    /** Human-readable name. */
    default String name() {
        return id().name();
    }

    /** Authenticate a request (credentials, assertion, ticket, etc.). */
    AuthResult authenticate(AuthRequest request);

    /** Issue a new token. */
    TokenResult issueToken(TokenRequest request);

    /** Rotate (refresh) an existing token. */
    TokenResult rotateToken(TokenRequest request);

    /** Revoke a token or all tokens for a principal. */
    void revokeToken(RevokeRequest request);

    /** Perform authorization check against the current context. */
    boolean authorize(AuthorizationContext ctx);

    /** Whether this provider supports the given capability. */
    default boolean supports(String capability) {
        return false;
    }
}
