package io.a2.provider.kerberos;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.SimplePrincipal;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Kerberos / SPNEGO ProtocolProvider.
 *
 * In a real deployment this would:
 * - Accept Negotiate tokens from the browser / client
 * - Call GSSContext.acceptSecContext (Java GSS-API)
 * - Extract the Kerberos principal (user@REALM)
 *
 * This scaffold accepts a Base64 SPNEGO token or a simple "user@REALM" string
 * for testing and maps it to an A2 Principal.
 */
public class KerberosProtocolProvider implements ProtocolProvider {

    private static final Logger log = LoggerFactory.getLogger(KerberosProtocolProvider.class);

    private final String servicePrincipal;
    private final String realm;
    private final Map<String, TicketRecord> tickets = new ConcurrentHashMap<>();

    public KerberosProtocolProvider() {
        this(
                System.getProperty("a2.kerberos.service-principal", "HTTP/server.example.com"),
                System.getProperty("a2.kerberos.realm", "EXAMPLE.COM")
        );
    }

    public KerberosProtocolProvider(String servicePrincipal, String realm) {
        this.servicePrincipal = servicePrincipal;
        this.realm = realm;
    }

    @Override
    public Protocol id() {
        return Protocol.KERBEROS;
    }

    @Override
    public String name() {
        return "Kerberos / SPNEGO";
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        String token = request.credentials();
        if (token == null || token.isBlank()) {
            token = request.headers().getOrDefault("Authorization", "");
            if (token.toLowerCase().startsWith("negotiate ")) {
                token = token.substring(10).trim();
            }
        }
        if (token == null || token.isBlank()) {
            return AuthResult.failure("Missing Negotiate / Kerberos token");
        }

        // Production: use GSSManager / GSSContext to accept the token.
        // Scaffold: accept either a Base64 blob or a plain principal string.
        String principalName;
        try {
            byte[] decoded = Base64.getDecoder().decode(token);
            // In real life the GSS accept would yield the principal.
            // Here we treat the decoded bytes as UTF-8 principal for tests.
            principalName = new String(decoded).trim();
            if (principalName.isEmpty()) {
                principalName = "user@" + realm;
            }
        } catch (IllegalArgumentException e) {
            // not Base64 – treat as already a principal name
            principalName = token.trim();
        }

        if (!principalName.contains("@")) {
            principalName = principalName + "@" + realm;
        }

        String sessionId = UUID.randomUUID().toString();
        tickets.put(sessionId, new TicketRecord(principalName, Instant.now().plusSeconds(8 * 3600)));

        log.debug("Kerberos auth success for {}", principalName);
        return AuthResult.success(
                SimplePrincipal.of(principalName, principalName.split("@")[0], "user"),
                Map.of("sessionId", sessionId, "realm", realm)
        );
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
        String tokenId = UUID.randomUUID().toString();
        Instant exp = Instant.now().plusSeconds(request.ttlSeconds() > 0 ? request.ttlSeconds() : 8 * 3600);
        tickets.put(tokenId, new TicketRecord(request.principalId(), exp));
        return TokenResult.success("krb." + tokenId, tokenId, TokenType.SESSION, exp);
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        if (request.existingToken() != null) {
            tickets.remove(request.existingToken().replace("krb.", ""));
        }
        return issueToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        if (request.tokenId() != null) {
            tickets.remove(request.tokenId());
            tickets.remove(request.tokenId().replace("krb.", ""));
        }
        if (request.allForPrincipal() && request.principalId() != null) {
            tickets.entrySet().removeIf(e -> request.principalId().equals(e.getValue().principal));
        }
    }

    @Override
    public boolean authorize(AuthorizationContext ctx) {
        if (ctx.principal() == null) return false;
        if (ctx.requiredRoles().isEmpty() && ctx.requiredPermissions().isEmpty()) return true;
        var p = ctx.principal();
        if (ctx.requireAll()) {
            return p.getRoles().containsAll(ctx.requiredRoles())
                    && p.getPermissions().containsAll(ctx.requiredPermissions());
        }
        boolean roleOk = ctx.requiredRoles().isEmpty()
                || ctx.requiredRoles().stream().anyMatch(p::hasRole);
        boolean permOk = ctx.requiredPermissions().isEmpty()
                || ctx.requiredPermissions().stream().anyMatch(perm -> p.getPermissions().contains(perm));
        return roleOk || permOk;
    }

    @Override
    public boolean supports(String capability) {
        return switch (capability) {
            case "spnego", "gss", "ticket" -> true;
            default -> false;
        };
    }

    private static final class TicketRecord {
        final String principal;
        final Instant expiresAt;

        TicketRecord(String principal, Instant expiresAt) {
            this.principal = principal;
            this.expiresAt = expiresAt;
        }
    }
}
