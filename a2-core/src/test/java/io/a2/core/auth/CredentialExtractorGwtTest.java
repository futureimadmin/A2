package io.a2.core.auth;

import io.a2.annotations.Protocol;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CredentialExtractor — GivenWhenThen")
class CredentialExtractorGwtTest {

    private static CredentialExtractor.HeaderLookup hdr(Map<String, String> map) {
        Map<String, String> lower = new HashMap<>();
        map.forEach((k, v) -> lower.put(k.toLowerCase(), v));
        return n -> lower.get(n.toLowerCase());
    }

    @Nested
    @DisplayName("Given Authorization Bearer")
    class Bearer {

        @Test
        @DisplayName("When three-part JWT, Then preferred=JWT")
        void givenJwtShape_whenExtract_thenJwt() {
            var e = CredentialExtractor.extract(hdr(Map.of("Authorization", "Bearer a.b.c")));
            assertEquals("a.b.c", e.credentials());
            assertEquals(Protocol.JWT, e.preferred());
        }

        @Test
        @DisplayName("When opaque bearer and SSO header, Then preferred=SSO")
        void givenOpaqueWithSso_whenExtract_thenSso() {
            var e = CredentialExtractor.extract(hdr(Map.of(
                    "Authorization", "Bearer opaque-token",
                    "X-A2-SSO-Provider", "okta")));
            assertEquals(Protocol.SSO, e.preferred());
            assertEquals("okta", e.ssoName());
        }

        @Test
        @DisplayName("When opaque bearer without SSO, Then preferred=OIDC")
        void givenOpaqueNoSso_whenExtract_thenOidc() {
            var e = CredentialExtractor.extract(hdr(Map.of("Authorization", "Bearer opaque")));
            assertEquals(Protocol.OIDC, e.preferred());
        }
    }

    @Nested
    @DisplayName("Given API key headers")
    class ApiKey {

        @Test
        @DisplayName("When X-API-Key present, Then preferred=API_KEY")
        void givenXApiKey_whenExtract_thenApiKey() {
            var e = CredentialExtractor.extract(hdr(Map.of("X-API-Key", "k1")));
            assertEquals("k1", e.credentials());
            assertEquals(Protocol.API_KEY, e.preferred());
        }

        @Test
        @DisplayName("When Authorization ApiKey scheme, Then preferred=API_KEY")
        void givenApiKeyScheme_whenExtract_thenApiKey() {
            var e = CredentialExtractor.extract(hdr(Map.of("Authorization", "ApiKey secret")));
            assertEquals("secret", e.credentials());
            assertEquals(Protocol.API_KEY, e.preferred());
        }
    }

    @Nested
    @DisplayName("Given Kerberos / Basic")
    class OtherSchemes {

        @Test
        @DisplayName("When Negotiate, Then preferred=KERBEROS")
        void givenNegotiate_whenExtract_thenKerberos() {
            var e = CredentialExtractor.extract(hdr(Map.of("Authorization", "Negotiate ticket")));
            assertEquals(Protocol.KERBEROS, e.preferred());
            assertEquals("ticket", e.credentials());
        }

        @Test
        @DisplayName("When Basic, Then preferred=BASIC")
        void givenBasic_whenExtract_thenBasic() {
            var e = CredentialExtractor.extract(hdr(Map.of("Authorization", "Basic dXNlcjpwYXNz")));
            assertEquals(Protocol.BASIC, e.preferred());
        }
    }

    @Nested
    @DisplayName("Given empty headers")
    class Empty {

        @Test
        @DisplayName("When no credentials, Then isEmpty true")
        void givenNone_whenExtract_thenEmpty() {
            var e = CredentialExtractor.extract(hdr(Map.of()));
            assertTrue(e.isEmpty());
            assertNull(e.preferred());
        }
    }
}
