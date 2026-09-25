package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Google Cloud Secret Manager backed TokenStore.
 *
 * Each token is stored as a secret named {@code a2-token-{tokenId}}.
 * Uses a thin {@link GcpSecretClient} SPI so the official Google client
 * library is optional.
 *
 * Note: Secret Manager is optimised for secrets, not high-churn token
 * workloads. Prefer Redis/Valkey for high QPS; use this for low-volume
 * long-lived credentials or audit-sensitive tokens.
 */
public class GcpSecretManagerTokenStore implements TokenStore {

    public interface GcpSecretClient {
        void createOrUpdateSecret(String secretId, byte[] payload);
        Optional<byte[]> accessSecret(String secretId);
        void deleteSecret(String secretId);
        List<String> listSecrets(String filterPrefix);
    }

    private final GcpSecretClient client;
    private final String prefix;
    /** Local index for principal → tokenIds (Secret Manager has no secondary index). */
    private final Map<String, List<String>> principalIndex = new ConcurrentHashMap<>();
    private final Map<String, String> valueIndex = new ConcurrentHashMap<>();

    public GcpSecretManagerTokenStore(GcpSecretClient client) {
        this(client, "a2-token-");
    }

    public GcpSecretManagerTokenStore(GcpSecretClient client, String prefix) {
        this.client = client;
        this.prefix = prefix;
    }

    @Override
    public void save(TokenRecord record) {
        String payload = serialize(record);
        client.createOrUpdateSecret(prefix + record.tokenId(),
                payload.getBytes(StandardCharsets.UTF_8));
        valueIndex.put(record.tokenValue(), record.tokenId());
        principalIndex.computeIfAbsent(record.principalId(), k -> new ArrayList<>())
                .add(record.tokenId());
    }

    @Override
    public Optional<TokenRecord> findById(String tokenId) {
        return client.accessSecret(prefix + tokenId)
                .flatMap(bytes -> deserialize(new String(bytes, StandardCharsets.UTF_8)))
                .filter(r -> !r.revoked())
                .filter(r -> r.expiresAt().isAfter(Instant.now()));
    }

    @Override
    public Optional<TokenRecord> findByTokenValue(String tokenValue) {
        String id = valueIndex.get(tokenValue);
        if (id == null) return Optional.empty();
        return findById(id);
    }

    @Override
    public List<TokenRecord> findByPrincipal(String principalId) {
        List<String> ids = principalIndex.getOrDefault(principalId, List.of());
        List<TokenRecord> out = new ArrayList<>();
        for (String id : ids) {
            findById(id).ifPresent(out::add);
        }
        return out;
    }

    @Override
    public void revoke(String tokenId) {
        findById(tokenId).ifPresent(r -> {
            TokenRecord revoked = new TokenRecord(
                    r.tokenId(), r.tokenValue(), r.type(), r.principalId(), r.issuer(),
                    r.issuedAt(), r.expiresAt(), true, r.assumedRole(),
                    r.impersonatedBy(), r.claims());
            save(revoked);
        });
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        List<String> ids = principalIndex.getOrDefault(principalId, List.of());
        ids.forEach(this::revoke);
    }

    @Override
    public int purgeExpired() {
        List<String> secrets = client.listSecrets(prefix);
        int purged = 0;
        for (String name : secrets) {
            String id = name.startsWith(prefix) ? name.substring(prefix.length()) : name;
            Optional<TokenRecord> r = client.accessSecret(name)
                    .flatMap(b -> deserialize(new String(b, StandardCharsets.UTF_8)));
            if (r.isPresent() && (r.get().expiresAt().isBefore(Instant.now()) || r.get().revoked())) {
                client.deleteSecret(name);
                purged++;
            }
        }
        return purged;
    }

    private static String serialize(TokenRecord r) {
        // minimal line-oriented format; use JSON in production
        return String.join("|",
                r.tokenId(),
                r.tokenValue(),
                r.type().name(),
                r.principalId(),
                r.issuer() != null ? r.issuer() : "",
                String.valueOf(r.issuedAt().getEpochSecond()),
                String.valueOf(r.expiresAt().getEpochSecond()),
                String.valueOf(r.revoked()),
                r.assumedRole() != null ? r.assumedRole() : "",
                r.impersonatedBy() != null ? r.impersonatedBy() : ""
        );
    }

    private static Optional<TokenRecord> deserialize(String s) {
        try {
            String[] p = s.split("\\|", -1);
            if (p.length < 10) return Optional.empty();
            return Optional.of(new TokenRecord(
                    p[0], p[1], TokenType.valueOf(p[2]), p[3],
                    p[4].isEmpty() ? null : p[4],
                    Instant.ofEpochSecond(Long.parseLong(p[5])),
                    Instant.ofEpochSecond(Long.parseLong(p[6])),
                    Boolean.parseBoolean(p[7]),
                    p[8].isEmpty() ? null : p[8],
                    p[9].isEmpty() ? null : p[9],
                    Map.of()
            ));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
