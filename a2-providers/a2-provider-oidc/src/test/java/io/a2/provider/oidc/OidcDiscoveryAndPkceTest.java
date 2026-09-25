package io.a2.provider.oidc;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OidcDiscoveryAndPkceTest {

    @Test
    void parseDiscoveryDocument() {
        String json = """
            {
              "issuer": "https://idp.example.com",
              "authorization_endpoint": "https://idp.example.com/auth",
              "token_endpoint": "https://idp.example.com/token",
              "jwks_uri": "https://idp.example.com/jwks",
              "userinfo_endpoint": "https://idp.example.com/userinfo",
              "revocation_endpoint": "https://idp.example.com/revoke",
              "introspection_endpoint": "https://idp.example.com/introspect",
              "scopes_supported": ["openid", "profile", "email"],
              "response_types_supported": ["code"],
              "subject_types_supported": ["public"],
              "id_token_signing_alg_values_supported": ["RS256"],
              "token_endpoint_auth_methods_supported": ["client_secret_basic"],
              "claims_supported": ["sub", "name", "email"]
            }
            """;

        OidcDiscoveryClient client = new OidcDiscoveryClient();
        OidcDiscoveryDocument doc = client.parse(json, "https://idp.example.com/.well-known/openid-configuration");

        assertEquals("https://idp.example.com", doc.getIssuer());
        assertEquals(URI.create("https://idp.example.com/token"), doc.getTokenEndpoint());
        assertEquals(URI.create("https://idp.example.com/jwks"), doc.getJwksUri());
        assertTrue(doc.getScopesSupported().contains("openid"));
        assertTrue(doc.getIdTokenSigningAlgValuesSupported().contains("RS256"));
    }

    @Test
    void normalizeDiscoveryUri() {
        assertEquals(
                "https://idp.example.com/.well-known/openid-configuration",
                OidcDiscoveryClient.normalizeDiscoveryUri("https://idp.example.com"));
        assertEquals(
                "https://idp.example.com/.well-known/openid-configuration",
                OidcDiscoveryClient.normalizeDiscoveryUri("https://idp.example.com/"));
        assertEquals(
                "https://idp.example.com/.well-known/openid-configuration",
                OidcDiscoveryClient.normalizeDiscoveryUri(
                        "https://idp.example.com/.well-known/openid-configuration"));
    }

    @Test
    void missingIssuerFails() {
        OidcDiscoveryClient client = new OidcDiscoveryClient();
        assertThrows(OidcDiscoveryClient.OidcDiscoveryException.class,
                () -> client.parse("{\"token_endpoint\":\"https://x\"}", "test"));
    }

    @Test
    void pkceFlowGeneratesChallengeAndExchange() {
        OidcDiscoveryDocument doc = OidcDiscoveryDocument.builder()
                .issuer("https://idp.example.com")
                .authorizationEndpoint(URI.create("https://idp.example.com/auth"))
                .tokenEndpoint(URI.create("https://idp.example.com/token"))
                .jwksUri(URI.create("https://idp.example.com/jwks"))
                .scopesSupported(List.of("openid"))
                .build();

        OidcAuthCodeFlow flow = new OidcAuthCodeFlow(doc, "my-client", "https://app.example.com/callback");
        OidcAuthCodeFlow.AuthRedirect redirect = flow.start("openid profile");

        assertNotNull(redirect.authorizationUrl());
        assertTrue(redirect.authorizationUrl().contains("code_challenge="));
        assertTrue(redirect.authorizationUrl().contains("code_challenge_method=S256"));
        assertTrue(redirect.authorizationUrl().contains("state="));
        assertTrue(redirect.authorizationUrl().contains("nonce="));
        assertNotNull(redirect.codeVerifier());
        assertTrue(redirect.codeVerifier().length() >= 43);

        OidcAuthCodeFlow.TokenExchangeRequest exchange =
                flow.prepareTokenExchange("auth-code-xyz", redirect.state());
        assertEquals("https://idp.example.com/token", exchange.tokenEndpoint());
        assertTrue(exchange.formBody().contains("code=auth-code-xyz"));
        assertTrue(exchange.formBody().contains("code_verifier="));
        assertTrue(exchange.formBody().contains("grant_type=authorization_code"));
    }

    @Test
    void pkceRejectsUnknownState() {
        OidcDiscoveryDocument doc = OidcDiscoveryDocument.builder()
                .issuer("https://idp.example.com")
                .authorizationEndpoint(URI.create("https://idp.example.com/auth"))
                .tokenEndpoint(URI.create("https://idp.example.com/token"))
                .build();
        OidcAuthCodeFlow flow = new OidcAuthCodeFlow(doc, "c", "https://app/callback");
        assertThrows(IllegalStateException.class,
                () -> flow.prepareTokenExchange("code", "unknown-state"));
    }
}
