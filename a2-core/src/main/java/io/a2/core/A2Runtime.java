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
 * Holds the provider registry (by protocol and by name) and the current security context.
 */
public final class A2Runtime {

    private static final A2Runtime INSTANCE = new A2Runtime();

    private final Map<Protocol, ProtocolProvider> providers = new ConcurrentHashMap<>();
    /** Named providers for multi-SSO (okta, google, entra, …). */
    private final Map<String, ProtocolProvider> namedProviders = new ConcurrentHashMap<>();
    private final ThreadLocal<SecurityContext> contextHolder = ThreadLocal.withInitial(SecurityContext::anonymous);
    private TokenService tokenService;

    private A2Runtime() {}

    public static A2Runtime get() {
        return INSTANCE;
    }

    public void register(ProtocolProvider provider) {
        providers.put(provider.id(), provider);
    }

    /**
     * Register a provider under a stable name (e.g. {@code "okta"}, {@code "google"}).
     * Used so multiple SSO IdPs can coexist alongside the single {@link Protocol#SSO} slot.
     */
    public void registerNamed(String name, ProtocolProvider provider) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("provider name must not be blank");
        }
        namedProviders.put(name.toLowerCase(), provider);
        providers.putIfAbsent(provider.id(), provider);
    }

    public Optional<ProtocolProvider> provider(Protocol protocol) {
        return Optional.ofNullable(providers.get(protocol));
    }

    public Optional<ProtocolProvider> namedProvider(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(namedProviders.get(name.toLowerCase()));
    }

    public Collection<ProtocolProvider> providers() {
        return providers.values();
    }

    public Collection<ProtocolProvider> namedProviders() {
        return namedProviders.values();
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
        ProtocolProvider provider = null;
        Object ssoName = request.attributes() != null ? request.attributes().get("a2.sso.name") : null;
        if (ssoName != null) {
            provider = namedProviders.get(String.valueOf(ssoName).toLowerCase());
        }
        if (provider == null && request.protocol() != null) {
            provider = providers.get(request.protocol());
        }
        if (provider == null) {
            return AuthResult.failure("No provider registered for protocol: " + request.protocol());
        }
        return provider.authenticate(request);
    }
}
