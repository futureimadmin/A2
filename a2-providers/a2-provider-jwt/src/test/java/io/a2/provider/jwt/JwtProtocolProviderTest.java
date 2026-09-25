package io.a2.provider.jwt;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.store.InMemoryTokenStore;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.TokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtProtocolProviderTest {

    private JwtProtocolProvider provider;

    @BeforeEach
    void setUp() {
        provider = new JwtProtocolProvider(
                "a2-dev-secret-change-me-must-be-at-least-32-bytes-long!!",
                "https://a2.test",
                new InMemoryTokenStore()
        );
    }

    @Test
    void issueAndAuthenticate() {
        var issued = provider.issueToken(TokenRequest.builder()
                .type(TokenType.ACCESS)
                .principalId("alice")
                .ttlSeconds(600)
                .protocol(Protocol.JWT)
                .build());

        assertTrue(issued.isSuccess());
        assertTrue(issued.token().isPresent());

        var auth = provider.authenticate(AuthRequest.builder()
                .protocol(Protocol.JWT)
                .credentials(issued.token().get())
                .build());

        assertTrue(auth.isSuccess());
        assertEquals("alice", auth.principal().get().getId());
    }

    @Test
    void rejectTamperedToken() {
        var issued = provider.issueToken(TokenRequest.builder()
                .principalId("bob")
                .ttlSeconds(600)
                .build());
        String tampered = issued.token().get() + "x";
        var auth = provider.authenticate(AuthRequest.builder()
                .credentials(tampered)
                .build());
        assertFalse(auth.isSuccess());
    }

    @Test
    void idIsJwt() {
        assertEquals(Protocol.JWT, provider.id());
        assertTrue(provider.supports("hs256"));
        assertTrue(provider.supports("rs256"));
    }
}
