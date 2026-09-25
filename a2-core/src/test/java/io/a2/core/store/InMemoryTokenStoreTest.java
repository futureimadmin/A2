package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryTokenStoreTest {

    private InMemoryTokenStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryTokenStore();
    }

    @Test
    void saveAndFindById() {
        var record = new TokenStore.TokenRecord(
                "tid-1", "tok-value", TokenType.ACCESS, "user-1", "a2",
                Instant.now(), Instant.now().plusSeconds(3600), false,
                null, null, Map.of("k", "v")
        );
        store.save(record);

        assertTrue(store.findById("tid-1").isPresent());
        assertEquals("user-1", store.findById("tid-1").get().principalId());
    }

    @Test
    void findByTokenValue() {
        store.save(new TokenStore.TokenRecord(
                "tid-2", "secret-token", TokenType.ACCESS, "user-2", "a2",
                Instant.now(), Instant.now().plusSeconds(3600), false,
                null, null, Map.of()
        ));
        assertTrue(store.findByTokenValue("secret-token").isPresent());
    }

    @Test
    void revoke() {
        store.save(new TokenStore.TokenRecord(
                "tid-3", "tok3", TokenType.ACCESS, "user-3", "a2",
                Instant.now(), Instant.now().plusSeconds(3600), false,
                null, null, Map.of()
        ));
        store.revoke("tid-3");
        assertTrue(store.findById("tid-3").isEmpty());
    }

    @Test
    void revokeAllForPrincipal() {
        store.save(new TokenStore.TokenRecord(
                "t1", "v1", TokenType.ACCESS, "alice", "a2",
                Instant.now(), Instant.now().plusSeconds(3600), false, null, null, Map.of()));
        store.save(new TokenStore.TokenRecord(
                "t2", "v2", TokenType.REFRESH, "alice", "a2",
                Instant.now(), Instant.now().plusSeconds(7200), false, null, null, Map.of()));
        store.revokeAllForPrincipal("alice");
        assertTrue(store.findByPrincipal("alice").isEmpty());
    }

    @Test
    void expiredTokenNotReturned() {
        store.save(new TokenStore.TokenRecord(
                "expired", "ev", TokenType.ACCESS, "bob", "a2",
                Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600),
                false, null, null, Map.of()));
        assertTrue(store.findById("expired").isEmpty());
    }
}
