package io.a2.provider.oidc;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenID Connect Authorization Code + PKCE (S256) helper.
 *
 * Specs:
 * - OIDC Core: authorization code flow
 * - RFC 7636: PKCE
 */
public class OidcAuthCodeFlow {

    private final OidcDiscoveryDocument discovery;
    private final String clientId;
    private final String redirectUri;
    private final SecureRandom random = new SecureRandom();

    /** state -> PkceSession */
    private final Map<String, PkceSession> sessions = new ConcurrentHashMap<>();

    public OidcAuthCodeFlow(OidcDiscoveryDocument discovery, String clientId, String redirectUri) {
        this.discovery = discovery;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
    }

    /**
     * Build the authorization URL and remember the PKCE verifier for the callback.
     */
    public AuthRedirect start(String scope) {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        String verifier = generateCodeVerifier();
        String challenge = codeChallengeS256(verifier);

        sessions.put(state, new PkceSession(verifier, nonce, System.currentTimeMillis() + 600_000));

        StringBuilder url = new StringBuilder(discovery.getAuthorizationEndpoint().toString());
        url.append(url.indexOf("?") >= 0 ? "&" : "?");
        url.append("response_type=code");
        url.append("&client_id=").append(enc(clientId));
        url.append("&redirect_uri=").append(enc(redirectUri));
        url.append("&scope=").append(enc(scope != null ? scope : "openid profile email"));
        url.append("&state=").append(enc(state));
        url.append("&nonce=").append(enc(nonce));
        url.append("&code_challenge=").append(enc(challenge));
        url.append("&code_challenge_method=S256");

        return new AuthRedirect(url.toString(), state, nonce, verifier);
    }

    /**
     * Exchange authorization code for tokens (caller supplies HTTP).
     * Returns the form body to POST to the token endpoint.
     */
    public TokenExchangeRequest prepareTokenExchange(String code, String state) {
        PkceSession session = sessions.remove(state);
        if (session == null || session.expiresAt < System.currentTimeMillis()) {
            throw new IllegalStateException("Invalid or expired state/PKCE session");
        }
        String body = "grant_type=authorization_code"
                + "&code=" + enc(code)
                + "&redirect_uri=" + enc(redirectUri)
                + "&client_id=" + enc(clientId)
                + "&code_verifier=" + enc(session.verifier);
        return new TokenExchangeRequest(discovery.getTokenEndpoint().toString(), body, session.nonce);
    }

    public void cleanupExpired() {
        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(e -> e.getValue().expiresAt < now);
    }

    private String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String codeChallengeS256(String verifier) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public record AuthRedirect(String authorizationUrl, String state, String nonce, String codeVerifier) {}
    public record TokenExchangeRequest(String tokenEndpoint, String formBody, String expectedNonce) {}

    private static final class PkceSession {
        final String verifier;
        final String nonce;
        final long expiresAt;

        PkceSession(String verifier, String nonce, long expiresAt) {
            this.verifier = verifier;
            this.nonce = nonce;
            this.expiresAt = expiresAt;
        }
    }
}
