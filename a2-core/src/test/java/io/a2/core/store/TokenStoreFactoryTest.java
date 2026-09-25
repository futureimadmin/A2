package io.a2.core.store;

import io.a2.spi.TokenStore;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TokenStoreFactoryTest {

    @Test
    void createsInMemory() {
        TokenStore store = TokenStoreFactory.create("memory", Map.of());
        assertInstanceOf(InMemoryTokenStore.class, store);
    }

    @Test
    void createsInMemoryAliases() {
        assertInstanceOf(InMemoryTokenStore.class, TokenStoreFactory.create("in-memory", Map.of()));
        assertInstanceOf(InMemoryTokenStore.class, TokenStoreFactory.create(null, Map.of()));
    }

    @Test
    void unknownTypeThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("cassandra", Map.of()));
    }

    @Test
    void jdbcRequiresDataSource() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("jdbc", Map.of()));
    }

    @Test
    void redisRequiresCommands() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("redis", Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("valkey", Map.of()));
    }

    @Test
    void vaultRequiresClient() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("vault", Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("tmvault", Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("openbao", Map.of()));
    }

    @Test
    void gcpRequiresClient() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenStoreFactory.create("gcp-secretmanager", Map.of()));
    }
}
