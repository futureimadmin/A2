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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SAML 2.0 ProtocolProvider (Service Provider side).
 *
 * Package: {@code io.a2.provider.saml}
 *
 * Performs full assertion validation via {@link SamlAssertionValidator}:
 * Issuer, Audience, Conditions (NotBefore/NotOnOrAfter), NameID, Attributes,
 * and optional XML-DSig verification against the IdP certificate.
 */
public class SamlProtocolProvider implements ProtocolProvider {

    private static final Logger log = LoggerFactory.getLogger(SamlProtocolProvider.class);

    private final String entityId;
    private final String idpSsoUrl;
    private final String acsUrl;
    private final String expectedIdpIssuer;
    private final X509Certificate idpCertificate;
    private final SamlAssertionValidator validator;
    private final Map<String, AssertionRecord> sessions = new ConcurrentHashMap<>();

    public SamlProtocolProvider() {
        this(
                System.getProperty("a2.saml.entity-id", "https://sp.example.com"),
                System.getProperty("a2.saml.idp-sso-url", "https://idp.example.com/sso"),
                System.getProperty("a2.saml.acs-url", "https://sp.example.com/acs"),
                System.getProperty("a2.saml.idp-issuer", null),
                null
        );
    }

    public SamlProtocolProvider(String entityId, String idpSsoUrl, String acsUrl) {
        this(entityId, idpSsoUrl, acsUrl, null, null);
    }

    public SamlProtocolProvider(String entityId, String idpSsoUrl, String acsUrl,
                                String expectedIdpIssuer, X509Certificate idpCertificate) {
        this.entityId = entityId;
        this.idpSsoUrl = idpSsoUrl;
        this.acsUrl = acsUrl;
        this.expectedIdpIssuer = expectedIdpIssuer;
        this.idpCertificate = idpCertificate;
        this.validator = new SamlAssertionValidator(entityId, expectedIdpIssuer, idpCertificate, 120);
    }

    /** Builder-style factory that also accepts a PEM certificate string. */
    public static SamlProtocolProvider withIdpCertificate(String entityId, String idpSsoUrl,
                                                          String acsUrl, String idpIssuer,
                                                          String idpCertPem) throws Exception {
        X509Certificate cert = null;
        if (idpCertPem != null && !idpCertPem.isBlank()) {
            cert = SamlAssertionValidator.loadCertificateFromPem(idpCertPem);
        }
        return new SamlProtocolProvider(entityId, idpSsoUrl, acsUrl, idpIssuer, cert);
    }

    @Override
    public Protocol id() {
        return Protocol.SAML;
    }

    @Override
    public String name() {
        return "SAML 2.0";
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        String samlResponse = request.credentials();
        if (samlResponse == null || samlResponse.isBlank()) {
            // also accept from form-style attribute
            Object form = request.attributes().get("SAMLResponse");
            if (form != null) samlResponse = String.valueOf(form);
        }
        if (samlResponse == null || samlResponse.isBlank()) {
            return AuthResult.failure("Missing SAMLResponse");
        }

        SamlAssertionValidator.ValidationResult vr = validator.validate(samlResponse);
        if (!vr.isSuccess()) {
            log.debug("SAML validation failed: {}", vr.getError());
            return AuthResult.failure(vr.getError());
        }

        Set<String> roles = vr.rolesFromAttributes();
        Map<String, Object> attrs = new HashMap<>(vr.getAttributes());
        attrs.put("issuer", vr.getIssuer());
        attrs.put("audiences", vr.getAudiences());
        attrs.put("signatureValid", vr.isSignatureValid());
        if (vr.getSessionIndex() != null) {
            attrs.put("sessionIndex", vr.getSessionIndex());
        }

        String sessionKey = vr.getSessionIndex() != null
                ? vr.getSessionIndex()
                : UUID.randomUUID().toString();
        Instant expiry = vr.getNotOnOrAfter() != null
                ? vr.getNotOnOrAfter()
                : Instant.now().plusSeconds(3600);
        sessions.put(sessionKey, new AssertionRecord(vr.getNameId(), expiry));

        SimplePrincipal principal = new SimplePrincipal(
                vr.getNameId(), vr.getNameId(), roles, Set.of(), attrs);

        log.debug("SAML auth success for NameID={} issuer={} sigValid={}",
                vr.getNameId(), vr.getIssuer(), vr.isSignatureValid());

        return AuthResult.success(principal, attrs);
    }

    /**
     * Build a minimal AuthnRequest (caller handles Redirect/POST binding & signing).
     */
    public String buildAuthnRequest(String relayState) {
        String id = "_" + UUID.randomUUID();
        String issueInstant = Instant.now().toString();
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
        sb.append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
        sb.append("ID=\"").append(id).append("\" Version=\"2.0\" ");
        sb.append("IssueInstant=\"").append(issueInstant).append("\" ");
        sb.append("Destination=\"").append(idpSsoUrl).append("\" ");
        sb.append("AssertionConsumerServiceURL=\"").append(acsUrl).append("\" ");
        sb.append("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">");
        sb.append("<saml:Issuer>").append(entityId).append("</saml:Issuer>");
        sb.append("</samlp:AuthnRequest>");
        return sb.toString();
    }

    @Override
    public TokenResult issueToken(TokenRequest request) {
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
            case "authn_request", "acs", "assertion_validation",
                 "signature", "audience", "conditions", "single_logout" -> true;
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
