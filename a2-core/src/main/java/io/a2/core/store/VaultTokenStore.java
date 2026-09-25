package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * HashiCorp Vault (and TMVault / Vault-compatible) TokenStore.
 *
 * Stores each token as a KV secret under {@code secret/data/a2/tokens/{tokenId}}.
 * Uses a thin {@link VaultClient} SPI so you can plug the official Vault driver,
 * Spring Vault, or a simple HTTP client without hard dependencies.
 *
 * Compatible with:
 * - HashiCorp Vault
 * - TMVault (Vault-API compatible)
 * - OpenBao
 */
public class VaultTokenStore implements TokenStore {

    public interface VaultClient {
        /** Write a secret at path (KV v2 data path). */
        void write(String path, Map<String, Object> data);

        /** Read secret data at path; empty if missing. */
        Optional<Map<String, Object>> read(String path);

        /** Delete secret at path. */
        void delete(String path);

        /** List keys under a path prefix. */
        List<String> list(String path);
    }

    private final VaultClient vault;
    private final String mountPath; // e.g. "secret/data/a2/tokens"

    public VaultTokenStore(VaultClient vault) {
        this(vault, "secret/data/a2/tokens");
    }

    public VaultTokenStore(VaultClient vault, String mountPath) {
        this.vault = vault;
        this.mountPath = mountPath.endsWith("/") ? mountPath.substring(0, mountPath.length() - 1) : mountPath;
    }

    @Override
    public void save(TokenRecord record) {
        Map<String, Object> data = new HashMap<>();
        data.put("tokenId", record.tokenId());
        data.put("tokenValue", record.tokenValue());
        data.put("type", record.type().name());
        data.put("principalId", record.principalId());
        data.put("issuer", record.issuer());
        data.put("issuedAt", record.issuedAt().getEpochSecond());
        data.put("expiresAt", record.expiresAt().getEpochSecond());
        data.put("revoked", record.revoked());
        data.put("assumedRole", record.assumedRole());
        data.put("impersonatedBy", record.impersonatedBy());
        data.put("claims", record.claims());
        vault.write(mountPath + "/" + record.tokenId(), data);

        // secondary index by token value
        vault.write(mountPath + "/by-value/" + hash(record.tokenValue()),
                Map.of("tokenId", record.tokenId()));
        // principal index
        vault.write(mountPath + "/by-principal/" + record.principalId() + "/" + record.tokenId(),
                Map.of("tokenId", record.tokenId()));
    }

    @Override
    public Optional<TokenRecord> findById(String tokenId) {
        return vault.read(mountPath + "/" + tokenId).flatMap(this::toRecord)
                .filter(r -> !r.revoked())
                .filter(r -> r.expiresAt().isAfter(Instant.now()));
    }

    @Override
    public Optional<TokenRecord> findByTokenValue(String tokenValue) {
        return vault.read(mountPath + "/by-value/" + hash(tokenValue))
                .map(m -> String.valueOf(m.get("tokenId")))
                .flatMap(this::findById);
    }

    @Override
    public List<TokenRecord> findByPrincipal(String principalId) {
        List<String> keys = vault.list(mountPath + "/by-principal/" + principalId);
        List<TokenRecord> out = new ArrayList<>();
        for (String key : keys) {
            findById(key).ifPresent(out::add);
        }
        return out;
    }

    @Override
    public void revoke(String tokenId) {
        vault.read(mountPath + "/" + tokenId).ifPresent(data -> {
            data.put("revoked", true);
            vault.write(mountPath + "/" + tokenId, data);
        });
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        List<String> keys = vault.list(mountPath + "/by-principal/" + principalId);
        keys.forEach(this::revoke);
    }

    @Override
    public int purgeExpired() {
        List<String> keys = vault.list(mountPath);
        int purged = 0;
        for (String id : keys) {
            if (id.contains("/")) continue; // skip index paths
            Optional<Map<String, Object>> data = vault.read(mountPath + "/" + id);
            if (data.isEmpty()) continue;
            Optional<TokenRecord> r = toRecord(data.get());
            if (r.isPresent() && (r.get().expiresAt().isBefore(Instant.now()) || r.get().revoked())) {
                vault.delete(mountPath + "/" + id);
                purged++;
            }
        }
        return purged;
    }

    private Optional<TokenRecord> toRecord(Map<String, Object> d) {
        try {
            return Optional.of(new TokenRecord(
                    str(d, "tokenId"),
                    str(d, "tokenValue"),
                    TokenType.valueOf(str(d, "type") != null ? str(d, "type") : "ACCESS"),
                    str(d, "principalId"),
                    str(d, "issuer"),
                    Instant.ofEpochSecond(longVal(d, "issuedAt")),
                    Instant.ofEpochSecond(longVal(d, "expiresAt")),
                    boolVal(d, "revoked"),
                    str(d, "assumedRole"),
                    str(d, "impersonatedBy"),
                    mapVal(d, "claims")
            ));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : String.valueOf(v);
    }

    private static long longVal(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (v instanceof Number n) return n.longValue();
        if (v != null) return Long.parseLong(String.valueOf(v));
        return 0L;
    }

    private static boolean boolVal(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (v instanceof Boolean b) return b;
        return Boolean.parseBoolean(String.valueOf(v));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapVal(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (v instanceof Map<?, ?> map) return (Map<String, Object>) map;
        return Map.of();
    }

    private static String hash(String value) {
        // simple stable hash for path-safe index key
        return Integer.toHexString(value.hashCode());
    }
}
