package io.a2.core;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.TokenService;
import io.a2.spi.TokenStore;
import io.a2.spi.model.StoredToken;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * TokenService that persists every issued token via TokenStore
 * and delegates cryptographic work to the registered ProtocolProvider when available.
 */
public class PersistentTokenService implements TokenService {

    private final TokenStore store;

    public PersistentTokenService(TokenStore store) {
        this.store = store;
    }

    @Override
    public TokenResult issue(TokenRequest request) {
        Protocol protocol = request.protocol() != null ? request.protocol() : Protocol.JWT;
        Optional<ProtocolProvider> provider = A2Runtime.get().provider(protocol);

        TokenResult result;
        if (provider.isPresent()) {
            result = provider.get().issueToken(request);
        } else {
            // opaque fallback
            String tokenId = UUID.randomUUID().toString();
            String token = "a2." + tokenId;
            long ttl = request.ttlSeconds() > 0 ? request.ttlSeconds() : 3600;
            result = TokenResult.success(token, tokenId, request.type(),
                    Instant.now().plusSeconds(ttl), request.claims());
        }

        if (result.isSuccess()) {
            StoredToken stored = StoredToken.builder()
                    .tokenId(result.tokenId().orElse(UUID.randomUUID().toString()))
                    .rawToken(result.token().orElse(null))
                    .type(result.type().orElse(request.type()))
                    .principalId(request.principalId())
                    .protocol(protocol)
                    .issuedAt(Instant.now())
                    .expiresAt(result.expiresAt().orElse(null))
                    .claims(result.claims())
                    .build();
            store.save(stored);
        }
        return result;
    }

    @Override
    public TokenResult rotate(TokenRequest request) {
        if (request.existingToken() != null) {
            store.findByRawToken(request.existingToken())
                    .ifPresent(t -> store.revoke(t.tokenId()));
        }
        return issue(request);
    }

    @Override
    public void revoke(String tokenId) {
        store.revoke(tokenId);
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        store.revokeAllForPrincipal(principalId);
    }

    @Override
    public Optional<TokenResult> introspect(String token) {
        Optional<StoredToken> stored = store.findByRawToken(token);
        if (stored.isEmpty()) {
            // try by id
            stored = store.findById(token);
        }
        if (stored.isEmpty()) return Optional.empty();

        StoredToken t = stored.get();
        if (!t.isActive()) {
            return Optional.of(TokenResult.failure(t.revoked() ? "revoked" : "expired"));
        }
        return Optional.of(TokenResult.success(
                t.rawToken(), t.tokenId(), t.type(), t.expiresAt(), t.claims()));
    }
}
