package io.a2.spi;

import io.a2.annotations.TokenType;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.util.Optional;

/**
 * High-level token lifecycle service used by the runtime and by applications.
 */
public interface TokenService {

    TokenResult issue(TokenRequest request);

    TokenResult rotate(TokenRequest request);

    void revoke(String tokenId);

    void revokeAllForPrincipal(String principalId);

    Optional<TokenResult> introspect(String token);

    default TokenResult issueAccessToken(String principalId, String... scopes) {
        return issue(TokenRequest.builder()
                .type(TokenType.ACCESS)
                .principalId(principalId)
                .scopes(scopes)
                .build());
    }
}
