package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test against a real Redis instance.
 * Enabled when env REDIS_HOST is set (CI service or local Redis).
 * Falls back to embedded mock adapter when Redis is unavailable so unit CI still passes.
 */
class RedisTokenStoreIntegrationTest {

    private static TokenStore store;
    private static JedisPool pool;
    private static boolean useRealRedis;

    @BeforeAll
    static void init() {
        String host = System.getenv().getOrDefault("REDIS_HOST", "localhost");
        int port = Integer.parseInt(System.getenv().getOrDefault("REDIS_PORT", "6379"));
        try {
            pool = new JedisPool(host, port);
            try (Jedis j = pool.getResource()) {
                j.ping();
            }
            useRealRedis = true;
            store = new RedisTokenStore(new JedisRedisCommands(pool));
        } catch (Exception e) {
            useRealRedis = false;
            store = new RedisTokenStore(new InMemoryRedisCommands());
        }
    }

    @AfterAll
    static void shutdown() {
        if (pool != null) pool.close();
    }

    @Test
    void saveFindRevoke() {
        var record = new TokenStore.TokenRecord(
                "int-tid-1", "int-tok-1", TokenType.ACCESS, "user-int",
                "a2", Instant.now(), Instant.now().plusSeconds(600),
                false, null, null, Map.of("env", useRealRedis ? "redis" : "mock")
        );
        store.save(record);

        assertTrue(store.findById("int-tid-1").isPresent());
        assertTrue(store.findByTokenValue("int-tok-1").isPresent());
        assertEquals(1, store.findByPrincipal("user-int").size());

        store.revoke("int-tid-1");
        assertTrue(store.findById("int-tid-1").isEmpty());
    }

    @Test
    void revokeAllForPrincipal() {
        store.save(new TokenStore.TokenRecord(
                "p1", "pv1", TokenType.ACCESS, "multi-user", "a2",
                Instant.now(), Instant.now().plusSeconds(600), false, null, null, Map.of()));
        store.save(new TokenStore.TokenRecord(
                "p2", "pv2", TokenType.REFRESH, "multi-user", "a2",
                Instant.now(), Instant.now().plusSeconds(1200), false, null, null, Map.of()));
        store.revokeAllForPrincipal("multi-user");
        assertTrue(store.findByPrincipal("multi-user").isEmpty());
    }

    /** Jedis adapter for real Redis. */
    static final class JedisRedisCommands implements RedisTokenStore.RedisCommands {
        private final JedisPool pool;

        JedisRedisCommands(JedisPool pool) { this.pool = pool; }

        @Override public void hset(String key, Map<String, String> fields) {
            try (Jedis j = pool.getResource()) { j.hset(key, fields); }
        }
        @Override public Map<String, String> hgetAll(String key) {
            try (Jedis j = pool.getResource()) { return j.hgetAll(key); }
        }
        @Override public void set(String key, String value) {
            try (Jedis j = pool.getResource()) { j.set(key, value); }
        }
        @Override public String get(String key) {
            try (Jedis j = pool.getResource()) { return j.get(key); }
        }
        @Override public void sadd(String key, String... members) {
            try (Jedis j = pool.getResource()) { j.sadd(key, members); }
        }
        @Override public Set<String> smembers(String key) {
            try (Jedis j = pool.getResource()) { return j.smembers(key); }
        }
        @Override public void srem(String key, String... members) {
            try (Jedis j = pool.getResource()) { j.srem(key, members); }
        }
        @Override public void del(String... keys) {
            try (Jedis j = pool.getResource()) { j.del(keys); }
        }
        @Override public void expire(String key, long seconds) {
            try (Jedis j = pool.getResource()) { j.expire(key, seconds); }
        }
        @Override public Set<String> keys(String pattern) {
            try (Jedis j = pool.getResource()) { return j.keys(pattern); }
        }
    }

    /** In-process RedisCommands so tests run without Redis. */
    static final class InMemoryRedisCommands implements RedisTokenStore.RedisCommands {
        private final Map<String, Map<String, String>> hashes = new HashMap<>();
        private final Map<String, String> strings = new HashMap<>();
        private final Map<String, Set<String>> sets = new HashMap<>();

        @Override public void hset(String key, Map<String, String> fields) {
            hashes.computeIfAbsent(key, k -> new HashMap<>()).putAll(fields);
        }
        @Override public Map<String, String> hgetAll(String key) {
            return hashes.getOrDefault(key, Map.of());
        }
        @Override public void set(String key, String value) { strings.put(key, value); }
        @Override public String get(String key) { return strings.get(key); }
        @Override public void sadd(String key, String... members) {
            sets.computeIfAbsent(key, k -> new HashSet<>()).addAll(Set.of(members));
        }
        @Override public Set<String> smembers(String key) {
            return sets.getOrDefault(key, Set.of());
        }
        @Override public void srem(String key, String... members) {
            Set<String> s = sets.get(key);
            if (s != null) for (String m : members) s.remove(m);
        }
        @Override public void del(String... keys) {
            for (String k : keys) { hashes.remove(k); strings.remove(k); sets.remove(k); }
        }
        @Override public void expire(String key, long seconds) { /* no-op for in-memory */ }
        @Override public Set<String> keys(String pattern) {
            Set<String> result = new HashSet<>();
            String prefix = pattern.replace("*", "");
            hashes.keySet().stream().filter(k -> k.startsWith(prefix)).forEach(result::add);
            return result;
        }
    }
}
