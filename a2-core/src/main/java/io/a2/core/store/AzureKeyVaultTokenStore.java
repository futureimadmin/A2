package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Azure Key Vault secrets backed TokenStore.
 *
 * Secret name: {@code a2-token-{tokenId}} (Key Vault names: alphanumeric + dashes).
 * Uses thin {@link AzureKeyVaultClient} SPI — Azure SDK optional.
 */
public class AzureKeyVaultTokenStore implements TokenStore {

    public interface AzureKeyVaultClient {
        void setSecret(String name, String value);
        Optional<String> getSecret(String name);
        void deleteSecret(String name);
        List<String> listSecretNames(String namePrefix);
    }

    private final AzureKeyVaultClient client;
    private final String prefix;
    private final Map<String, List<String>> principalIndex = new ConcurrentHashMap<>();
    private final Map<String, String> valueIndex = new ConcurrentHashMap<>();

    public AzureKeyVaultTokenStore(AzureKeyVaultClient client) {
        this(client, "a2-token-");
    }

    public AzureKeyVaultTokenStore(AzureKeyVaultClient client, String prefix) {
        this.client = client;
        this.prefix = prefix;
    }

    @Override
    public void save(TokenRecord record) {
        // Key Vault secret names cannot contain '/'
        String name = prefix + record.tokenId().replace('/', '-');
        client.setSecret(name, serialize(record));
        valueIndex.put(record.tokenValue(), record.tokenId());
        principalIndex.computeIfAbsent(record.principalId(), k -> new ArrayList<>()).add(record.tokenId());
    }

    @Override
    public Optional<TokenRecord> findById(String tokenId) {
        String name = prefix + tokenId.replace('/', '-');
        return client.getSecret(name)
                .flatMap(AzureKeyVaultTokenStore::deserialize)
                .filter(r -> !r.revoked())
                .filter(r -> r.expiresAt().isAfter(Instant.now()));
    }

    @Override
    public Optional<TokenRecord> findByTokenValue(String tokenValue) {
        String id = valueIndex.get(tokenValue);
        return id == null ? Optional.empty() : findById(id);
    }

    @Override
    public List<TokenRecord> findByPrincipal(String principalId) {
        List<TokenRecord> out = new ArrayList<>();
        for (String id : principalIndex.getOrDefault(principalId, List.of())) {
            findById(id).ifPresent(out::add);
        }
        return out;
    }

    @Override
    public void revoke(String tokenId) {
        findById(tokenId).ifPresent(r -> save(new TokenRecord(
                r.tokenId(), r.tokenValue(), r.type(), r.principalId(), r.issuer(),
                r.issuedAt(), r.expiresAt(), true, r.assumedRole(),
                r.impersonatedBy(), r.claims())));
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        principalIndex.getOrDefault(principalId, List.of()).forEach(this::revoke);
    }

    @Override
    public int purgeExpired() {
        int purged = 0;
        for (String name : client.listSecretNames(prefix)) {
            Optional<TokenRecord> r = client.getSecret(name).flatMap(AzureKeyVaultTokenStore::deserialize);
            if (r.isPresent() && (r.get().expiresAt().isBefore(Instant.now()) || r.get().revoked())) {
                client.deleteSecret(name);
                purged++;
            }
        }
        return purged;
    }

    private static String serialize(TokenRecord r) {
        return String.join("|",
                r.tokenId(), r.tokenValue(), r.type().name(), r.principalId(),
                r.issuer() != null ? r.issuer() : "",
                String.valueOf(r.issuedAt().getEpochSecond()),
                String.valueOf(r.expiresAt().getEpochSecond()),
                String.valueOf(r.revoked()),
                r.assumedRole() != null ? r.assumedRole() : "",
                r.impersonatedBy() != null ? r.impersonatedBy() : "");
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
                    Map.of()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
