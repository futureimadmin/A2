package io.a2.core;

import io.a2.annotations.Protocol;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.SecurityContext;
import io.a2.spi.TokenService;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central entry point for A2.
 * Holds the provider registry and the current security context (thread-local).
 */
public final class A2Runtime {

    private static final A2Runtime INSTANCE = new A2Runtime();

    private final Map<Protocol, ProtocolProvider> providers = new ConcurrentHashMap<>();
    private final ThreadLocal<SecurityContext> contextHolder = ThreadLocal.withInitial(SecurityContext::anonymous);
    private TokenService tokenService;

    private A2Runtime() {}

    public static A2Runtime get() {
        return INSTANCE;
    }

    public void register(ProtocolProvider provider) {
        providers.put(provider.id(), provider);
    }

    public Optional<ProtocolProvider> provider(Protocol protocol) {
        return Optional.ofNullable(providers.get(protocol));
    }

    public Collection<ProtocolProvider> providers() {
        return providers.values();
    }

    public void setTokenService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    public TokenService tokenService() {
        if (tokenService == null) {
            throw new IllegalStateException("TokenService not configured");
        }
        return tokenService;
    }

    public SecurityContext currentContext() {
        return contextHolder.get();
    }

    public void setContext(SecurityContext ctx) {
        contextHolder.set(ctx == null ? SecurityContext.anonymous() : ctx);
    }

    public void clearContext() {
        contextHolder.remove();
    }

    public AuthResult authenticate(AuthRequest request) {
        ProtocolProvider provider = providers.get(request.protocol());
        if (provider == null) {
            return AuthResult.failure("No provider registered for protocol: " + request.protocol());
        }
        return provider.authenticate(request);
    }
}
