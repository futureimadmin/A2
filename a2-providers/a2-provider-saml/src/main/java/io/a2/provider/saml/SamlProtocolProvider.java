package io.a2.provider.saml;

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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SAML 2.0 ProtocolProvider (Service Provider side).
 *
 * Handles:
 * - AuthnRequest generation (caller builds redirect/POST)
 * - Assertion Consumer Service (ACS) – validates SAMLResponse
 * - Attribute extraction → Principal
 * - Session / assertion lifetime
 *
 * This is a functional scaffold. Production deployments should use a battle-tested
 * library (OpenSAML, pac4j-saml, Spring Security SAML) and plug it behind this SPI.
 */
public class SamlProtocolProvider implements ProtocolProvider {

    private static final Logger log = LoggerFactory.getLogger(SamlProtocolProvider.class);

    private final String entityId;
    private final String idpSsoUrl;
    private final String acsUrl;
    private final Map<String, AssertionRecord> sessions = new ConcurrentHashMap<>();

    private static final Pattern NAMEID_PATTERN =
            Pattern.compile("<NameID[^>]*>([^<]+)</NameID>", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR_PATTERN =
            Pattern.compile("<Attribute Name=\"([^\"]+)\"[^>]*>\\s*<AttributeValue[^>]*>([^<]*)</AttributeValue>",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    public SamlProtocolProvider() {
        this(
                System.getProperty("a2.saml.entity-id", "https://sp.example.com"),
                System.getProperty("a2.saml.idp-sso-url", "https://idp.example.com/sso"),
                System.getProperty("a2.saml.acs-url", "https://sp.example.com/acs")
        );
    }

    public SamlProtocolProvider(String entityId, String idpSsoUrl, String acsUrl) {
        this.entityId = entityId;
        this.idpSsoUrl = idpSsoUrl;
        this.acsUrl = acsUrl;
    }

    @Override
    public Protocol id() {
        return Protocol.SAML;
    }

    @Override
    public String name() {
        return "SAML 2.0";
    }

    /**
     * credentials = Base64-encoded SAMLResponse (or the raw XML for tests).
     */
    @Override
    public AuthResult authenticate(AuthRequest request) {
        String samlResponse = request.credentials();
        if (samlResponse == null || samlResponse.isBlank()) {
            return AuthResult.failure("Missing SAMLResponse");
        }

        String xml;
        try {
            // try Base64 decode first
            xml = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            xml = samlResponse; // already plain XML
        }

        // Extremely simplified validation – production must verify signature, audience, conditions, etc.
        Matcher nameIdMatcher = NAMEID_PATTERN.matcher(xml);
        if (!nameIdMatcher.find()) {
            return AuthResult.failure("No NameID in SAML assertion");
        }
        String nameId = nameIdMatcher.group(1).trim();

        Map<String, Object> attrs = new java.util.HashMap<>();
        Matcher attrMatcher = ATTR_PATTERN.matcher(xml);
        while (attrMatcher.find()) {
            attrs.put(attrMatcher.group(1), attrMatcher.group(2).trim());
        }

        Set<String> roles = Set.of();
        if (attrs.containsKey("Role") || attrs.containsKey("roles")) {
            Object r = attrs.getOrDefault("Role", attrs.get("roles"));
            roles = Set.of(r.toString().split("[,;\\s]+"));
        }

        String sessionIndex = UUID.randomUUID().toString();
        sessions.put(sessionIndex, new AssertionRecord(nameId, Instant.now().plusSeconds(3600)));

        SimplePrincipal principal = new SimplePrincipal(nameId, nameId, roles, Set.of(), attrs);
        return AuthResult.success(principal, Map.of("sessionIndex", sessionIndex, "protocol", "SAML"));
    }

    /**
     * Builds a minimal AuthnRequest (caller is responsible for redirect / POST binding).
     */
    public String buildAuthnRequest(String relayState) {
        String id = "_" + UUID.randomUUID();
        String issueInstant = Instant.now().toString();
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
                + "ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\" "
                + "Destination=\"" + idpSsoUrl + "\" AssertionConsumerServiceURL=\"" + acsUrl + "\" "
                + "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">"
                + "<saml:Issuer>" + entityId + "</saml:Issuer>"
                + "</samlp:AuthnRequest>";
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
        // SAML typically uses the assertion itself as the session token
        String tokenId = UUID.randomUUID().toString();
        Instant exp = Instant.now().plusSeconds(request.ttlSeconds() > 0 ? request.ttlSeconds() : 3600);
        sessions.put(tokenId, new AssertionRecord(request.principalId(), exp));
        return TokenResult.success("saml-session." + tokenId, tokenId, TokenType.SESSION, exp);
    }

    @Override
    public TokenResult rotateToken(TokenRequest request) {
        if (request.existingToken() != null) {
            sessions.remove(request.existingToken().replace("saml-session.", ""));
        }
        return issueToken(request);
    }

    @Override
    public void revokeToken(RevokeRequest request) {
        if (request.tokenId() != null) {
            sessions.remove(request.tokenId());
            sessions.remove(request.tokenId().replace("saml-session.", ""));
        }
        if (request.allForPrincipal() && request.principalId() != null) {
            sessions.entrySet().removeIf(e -> request.principalId().equals(e.getValue().nameId));
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
            case "authn_request", "acs", "single_logout" -> true;
            default -> false;
        };
    }

    private static final class AssertionRecord {
        final String nameId;
        final Instant expiresAt;

        AssertionRecord(String nameId, Instant expiresAt) {
            this.nameId = nameId;
            this.expiresAt = expiresAt;
        }
    }
}
