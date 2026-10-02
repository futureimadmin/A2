package io.a2.core.auth;

import io.a2.annotations.Protocol;
import io.a2.core.A2Runtime;
import io.a2.core.DefaultSecurityContext;
import io.a2.core.exception.A2AuthenticationException;
import io.a2.spi.Principal;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.SecurityContext;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Framework-agnostic request authentication.
 * Resolves credentials, tries registered providers (preferred first), sets A2Runtime context.
 */
public final class RequestAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(RequestAuthenticator.class);

    private final A2Runtime runtime;

    public RequestAuthenticator() {
        this(A2Runtime.get());
    }

    public RequestAuthenticator(A2Runtime runtime) {
        this.runtime = runtime;
    }

    public SecurityContext authenticate(CredentialExtractor.HeaderLookup headerLookup, boolean required) {
        CredentialExtractor.Extracted extracted = CredentialExtractor.extract(headerLookup);

        if (extracted.isEmpty()) {
            if (required) {
                throw A2AuthenticationException.required();
            }
            SecurityContext anon = SecurityContext.anonymous();
            runtime.setContext(anon);
            return anon;
        }

        List<Protocol> order = buildTryOrder(extracted.preferred());
        Map<String, Object> attrs = new HashMap<>();
        if (extracted.ssoName() != null) {
            attrs.put("a2.sso.name", extracted.ssoName());
        }

        AuthResult lastFailure = null;
        for (Protocol protocol : order) {
            Optional<ProtocolProvider> provider = resolveProvider(protocol, extracted.ssoName());
            if (provider.isEmpty()) {
                continue;
            }
            AuthRequest req = AuthRequest.builder()
                    .protocol(protocol)
                    .credentials(extracted.credentials())
                    .headers(extracted.headers())
                    .attributes(attrs)
                    .build();
            try {
                AuthResult result = provider.get().authenticate(req);
                if (result.isSuccess() && result.principal().isPresent()) {
                    Principal p = result.principal().get();
                    Protocol effective = protocol;
                    if (extracted.ssoName() != null) {
                        effective = Protocol.SSO;
                    }
                    Map<String, Object> claims = new HashMap<>();
                    if (p.getAttributes() != null) claims.putAll(p.getAttributes());
                    if (result.extra() != null) claims.putAll(result.extra());
                    SecurityContext ctx = new DefaultSecurityContext(
                            p, effective, p.getRoles(), p.getPermissions(), claims, null);
                    runtime.setContext(ctx);
                    log.debug("A2 AuthN success protocol={} principal={}", effective, p.getId());
                    return ctx;
                }
                lastFailure = result;
            } catch (Exception e) {
                log.debug("Provider {} rejected credentials: {}", protocol, e.getMessage());
                lastFailure = AuthResult.failure(e.getMessage());
            }
        }

        String detail = lastFailure != null
                ? lastFailure.error().orElse("Token validation failed")
                : "No suitable ProtocolProvider registered";
        throw A2AuthenticationException.invalid(detail);
    }

    private Optional<ProtocolProvider> resolveProvider(Protocol protocol, String ssoName) {
        if (protocol == Protocol.SSO && ssoName != null) {
            Optional<ProtocolProvider> named = runtime.namedProvider(ssoName);
            if (named.isPresent()) {
                return named;
            }
        }
        return runtime.provider(protocol);
    }

    private static List<Protocol> buildTryOrder(Protocol preferred) {
        List<Protocol> order = new ArrayList<>();
        if (preferred != null) {
            order.add(preferred);
        }
        for (Protocol p : List.of(Protocol.JWT, Protocol.OIDC, Protocol.SSO, Protocol.OAUTH2,
                Protocol.API_KEY, Protocol.SAML, Protocol.KERBEROS)) {
            if (!order.contains(p)) {
                order.add(p);
            }
        }
        return order;
    }

    public void clear() {
        runtime.clearContext();
    }
}
