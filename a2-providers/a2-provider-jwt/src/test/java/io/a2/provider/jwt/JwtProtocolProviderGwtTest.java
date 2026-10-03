package io.a2.provider.jwt;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.store.InMemoryTokenStore;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JwtProtocolProvider — GivenWhenThen")
class JwtProtocolProviderGwtTest {

    private JwtProtocolProvider provider;

    @BeforeEach
    void setUp() {
        provider = new JwtProtocolProvider(
                "a2-dev-secret-change-me-must-be-at-least-32-bytes-long!!",
                "https://a2.test",
                new InMemoryTokenStore()
        );
    }

    @Nested
    @DisplayName("Given issued access token")
    class IssueAndAuth {

        @Test
        @DisplayName("When issue then authenticate, Then principal matches")
        void givenIssuedToken_whenAuthenticate_thenPrincipalAlice() {
            TokenResult issued = provider.issueToken(TokenRequest.builder()
                    .type(TokenType.ACCESS)
                    .principalId("alice")
                    .ttlSeconds(600)
                    .protocol(Protocol.JWT)
                    .build());
            assertTrue(issued.isSuccess());

            AuthResult auth = provider.authenticate(AuthRequest.builder()
                    .protocol(Protocol.JWT)
                    .credentials(issued.token().orElseThrow())
                    .build());
            assertTrue(auth.isSuccess());
            assertEquals("alice", auth.principal().orElseThrow().getId());
        }

        @Test
        @DisplayName("When token tampered, Then authentication fails")
        void givenTamperedToken_whenAuthenticate_thenFailure() {
            TokenResult issued = provider.issueToken(TokenRequest.builder()
                    .principalId("bob")
                    .ttlSeconds(600)
                    .protocol(Protocol.JWT)
                    .build());
            String token = issued.token().orElseThrow();
            String tampered = token.substring(0, token.length() - 4) + "XXXX";

            AuthResult auth = provider.authenticate(AuthRequest.builder()
                    .protocol(Protocol.JWT)
                    .credentials(tampered)
                    .build());
            assertFalse(auth.isSuccess());
        }
    }

    @Nested
    @DisplayName("Given provider identity")
    class Identity {
        @Test
        @DisplayName("When id(), Then JWT")
        void givenProvider_whenId_thenJwt() {
            assertEquals(Protocol.JWT, provider.id());
        }
    }
}
