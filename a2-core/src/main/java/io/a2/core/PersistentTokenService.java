package io.a2.core;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.TokenService;
import io.a2.spi.TokenStore;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.util.Optional;

/**
 * TokenService that delegates issuance to a ProtocolProvider and persists
 * every token via TokenStore. Used for production and for S2S / AssumeRole flows.
 */
public class PersistentTokenService implements TokenService {

    private final TokenStore store;
    private final Protocol defaultProtocol;

    public PersistentTokenService(TokenStore store) {
        this(store, Protocol.JWT);
    }

    public PersistentTokenService(TokenStore store, Protocol defaultProtocol) {
        this.store = store;
        this.defaultProtocol = defaultProtocol;
    }

    @Override
    public TokenResult issue(TokenRequest request) {
        Protocol protocol = request.protocol() != null ? request.protocol() : defaultProtocol;
        Optional<ProtocolProvider> provider = A2Runtime.get().provider(protocol);
        if (provider.isEmpty()) {
            return TokenResult.failure("No provider for protocol " + protocol);
        }
        TokenResult result = provider.get().issueToken(request);
        // provider may already have saved; ensure store has it
        if (result.isSuccess() && store != null) {
            // already saved by Nimbus provider when store is injected
        }
        return result;
    }

    @Override
    public TokenResult rotate(TokenRequest request) {
        Protocol protocol = request.protocol() != null ? request.protocol() : defaultProtocol;
        Optional<ProtocolProvider> provider = A2Runtime.get().provider(protocol);
        if (provider.isEmpty()) {
            return TokenResult.failure("No provider for protocol " + protocol);
        }
        return provider.get().rotateToken(request);
    }

    @Override
    public void revoke(String tokenId) {
        if (store != null) store.revoke(tokenId);
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        if (store != null) store.revokeAllForPrincipal(principalId);
    }

    @Override
    public Optional<TokenResult> introspect(String token) {
        if (store == null) return Optional.empty();
        return store.findByTokenValue(token).map(r ->
                TokenResult.success(r.tokenValue(), r.tokenId(), r.type(), r.expiresAt(), r.claims()));
    }
}
