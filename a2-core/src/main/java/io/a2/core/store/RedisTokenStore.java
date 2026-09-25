package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Redis / Valkey-backed TokenStore.
 *
 * Works with any Redis-protocol server (Redis, Valkey, KeyDB, Dragonfly).
 * Uses a thin {@link RedisCommands} SPI so callers can plug Jedis, Lettuce,
 * Redisson, or the Valkey Java client without hard dependencies.
 *
 * Key layout:
 *   a2:token:{tokenId}          → hash of token fields
 *   a2:tokenval:{tokenValue}    → tokenId
 *   a2:principal:{principalId}  → set of tokenIds
 */
public class RedisTokenStore implements TokenStore {

    public interface RedisCommands {
        void hset(String key, Map<String, String> fields);
        Map<String, String> hgetAll(String key);
        void set(String key, String value);
        String get(String key);
        void sadd(String key, String... members);
        Set<String> smembers(String key);
        void srem(String key, String... members);
        void del(String... keys);
        void expire(String key, long seconds);
        Set<String> keys(String pattern);
    }

    private static final String PREFIX = "a2:token:";
    private static final String VAL_PREFIX = "a2:tokenval:";
    private static final String PRINCIPAL_PREFIX = "a2:principal:";

    private final RedisCommands redis;

    public RedisTokenStore(RedisCommands redis) {
        this.redis = redis;
    }

    @Override
    public void save(TokenRecord record) {
        String key = PREFIX + record.tokenId();
        Map<String, String> fields = new HashMap<>();
        fields.put("tokenId", record.tokenId());
        fields.put("tokenValue", record.tokenValue());
        fields.put("type", record.type().name());
        fields.put("principalId", record.principalId());
        fields.put("issuer", nullToEmpty(record.issuer()));
        fields.put("issuedAt", String.valueOf(record.issuedAt().getEpochSecond()));
        fields.put("expiresAt", String.valueOf(record.expiresAt().getEpochSecond()));
        fields.put("revoked", String.valueOf(record.revoked()));
        fields.put("assumedRole", nullToEmpty(record.assumedRole()));
        fields.put("impersonatedBy", nullToEmpty(record.impersonatedBy()));
        fields.put("claims", claimsToString(record.claims()));

        redis.hset(key, fields);
        long ttl = Duration.between(Instant.now(), record.expiresAt()).getSeconds();
        if (ttl > 0) {
            redis.expire(key, ttl + 60); // small grace
        }
        redis.set(VAL_PREFIX + record.tokenValue(), record.tokenId());
        if (ttl > 0) {
            redis.expire(VAL_PREFIX + record.tokenValue(), ttl + 60);
        }
        redis.sadd(PRINCIPAL_PREFIX + record.principalId(), record.tokenId());
    }

    @Override
    public Optional<TokenRecord> findById(String tokenId) {
        Map<String, String> fields = redis.hgetAll(PREFIX + tokenId);
        if (fields == null || fields.isEmpty()) return Optional.empty();
        TokenRecord r = fromFields(fields);
        if (r.revoked() || r.expiresAt().isBefore(Instant.now())) return Optional.empty();
        return Optional.of(r);
    }

    @Override
    public Optional<TokenRecord> findByTokenValue(String tokenValue) {
        String id = redis.get(VAL_PREFIX + tokenValue);
        if (id == null) return Optional.empty();
        return findById(id);
    }

    @Override
    public List<TokenRecord> findByPrincipal(String principalId) {
        Set<String> ids = redis.smembers(PRINCIPAL_PREFIX + principalId);
        List<TokenRecord> out = new ArrayList<>();
        if (ids == null) return out;
        for (String id : ids) {
            findById(id).ifPresent(out::add);
        }
        return out;
    }

    @Override
    public void revoke(String tokenId) {
        Map<String, String> fields = redis.hgetAll(PREFIX + tokenId);
        if (fields == null || fields.isEmpty()) return;
        fields.put("revoked", "true");
        redis.hset(PREFIX + tokenId, fields);
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        Set<String> ids = redis.smembers(PRINCIPAL_PREFIX + principalId);
        if (ids != null) ids.forEach(this::revoke);
    }

    @Override
    public int purgeExpired() {
        // Redis TTLs handle expiry; this is a best-effort sweep
        Set<String> keys = redis.keys(PREFIX + "*");
        int purged = 0;
        if (keys == null) return 0;
        for (String key : keys) {
            Map<String, String> fields = redis.hgetAll(key);
            if (fields == null || fields.isEmpty()) continue;
            TokenRecord r = fromFields(fields);
            if (r.expiresAt().isBefore(Instant.now()) || r.revoked()) {
                redis.del(key, VAL_PREFIX + r.tokenValue());
                redis.srem(PRINCIPAL_PREFIX + r.principalId(), r.tokenId());
                purged++;
            }
        }
        return purged;
    }

    private static TokenRecord fromFields(Map<String, String> f) {
        return new TokenRecord(
                f.get("tokenId"),
                f.get("tokenValue"),
                TokenType.valueOf(f.getOrDefault("type", "ACCESS")),
                f.get("principalId"),
                emptyToNull(f.get("issuer")),
                Instant.ofEpochSecond(Long.parseLong(f.getOrDefault("issuedAt", "0"))),
                Instant.ofEpochSecond(Long.parseLong(f.getOrDefault("expiresAt", "0"))),
                Boolean.parseBoolean(f.getOrDefault("revoked", "false")),
                emptyToNull(f.get("assumedRole")),
                emptyToNull(f.get("impersonatedBy")),
                stringToClaims(f.get("claims"))
        );
    }

    private static String nullToEmpty(String s) { return s == null ? "" : s; }
    private static String emptyToNull(String s) { return s == null || s.isEmpty() ? null : s; }

    private static String claimsToString(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) return "{}";
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (var e : claims.entrySet()) {
            if (!first) sb.append(',');
            sb.append(e.getKey()).append('=').append(e.getValue());
            first = false;
        }
        return sb.append('}').toString();
    }

    private static Map<String, Object> stringToClaims(String s) {
        Map<String, Object> m = new HashMap<>();
        if (s == null || s.length() < 2) return m;
        // minimal; production should use Jackson
        return m;
    }
}
