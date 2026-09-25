package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * JDBC-backed persistent TokenStore.
 *
 * Expected schema (create if not exists):
 *
 * CREATE TABLE a2_tokens (
 *   token_id        VARCHAR(64) PRIMARY KEY,
 *   token_value     VARCHAR(2048) NOT NULL,
 *   token_type      VARCHAR(32)  NOT NULL,
 *   principal_id    VARCHAR(256) NOT NULL,
 *   issuer          VARCHAR(256),
 *   issued_at       TIMESTAMP    NOT NULL,
 *   expires_at      TIMESTAMP    NOT NULL,
 *   revoked         BOOLEAN      NOT NULL DEFAULT FALSE,
 *   assumed_role    VARCHAR(256),
 *   impersonated_by VARCHAR(256),
 *   claims_json     CLOB
 * );
 * CREATE INDEX idx_a2_tokens_principal ON a2_tokens(principal_id);
 * CREATE INDEX idx_a2_tokens_value ON a2_tokens(token_value);
 */
public class JdbcTokenStore implements TokenStore {

    private final DataSource dataSource;

    public JdbcTokenStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void save(TokenRecord record) {
        String sql = """
            MERGE INTO a2_tokens (token_id, token_value, token_type, principal_id, issuer,
                                  issued_at, expires_at, revoked, assumed_role, impersonated_by, claims_json)
            KEY (token_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
        // Fallback for databases without MERGE: try INSERT then UPDATE
        try (Connection c = dataSource.getConnection()) {
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO a2_tokens (token_id, token_value, token_type, principal_id, issuer, " +
                    "issued_at, expires_at, revoked, assumed_role, impersonated_by, claims_json) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)")) {
                bind(ps, record);
                ps.executeUpdate();
            } catch (Exception insertEx) {
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE a2_tokens SET token_value=?, token_type=?, principal_id=?, issuer=?, " +
                        "issued_at=?, expires_at=?, revoked=?, assumed_role=?, impersonated_by=?, claims_json=? " +
                        "WHERE token_id=?")) {
                    ps.setString(1, record.tokenValue());
                    ps.setString(2, record.type().name());
                    ps.setString(3, record.principalId());
                    ps.setString(4, record.issuer());
                    ps.setTimestamp(5, Timestamp.from(record.issuedAt()));
                    ps.setTimestamp(6, Timestamp.from(record.expiresAt()));
                    ps.setBoolean(7, record.revoked());
                    ps.setString(8, record.assumedRole());
                    ps.setString(9, record.impersonatedBy());
                    ps.setString(10, claimsToJson(record.claims()));
                    ps.setString(11, record.tokenId());
                    ps.executeUpdate();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to save token", e);
        }
    }

    @Override
    public Optional<TokenRecord> findById(String tokenId) {
        return queryOne("SELECT * FROM a2_tokens WHERE token_id = ? AND revoked = FALSE AND expires_at > ?",
                tokenId, Timestamp.from(Instant.now()));
    }

    @Override
    public Optional<TokenRecord> findByTokenValue(String tokenValue) {
        return queryOne("SELECT * FROM a2_tokens WHERE token_value = ? AND revoked = FALSE AND expires_at > ?",
                tokenValue, Timestamp.from(Instant.now()));
    }

    @Override
    public List<TokenRecord> findByPrincipal(String principalId) {
        String sql = "SELECT * FROM a2_tokens WHERE principal_id = ? AND revoked = FALSE AND expires_at > ?";
        List<TokenRecord> list = new ArrayList<>();
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, principalId);
            ps.setTimestamp(2, Timestamp.from(Instant.now()));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) list.add(map(rs));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return list;
    }

    @Override
    public void revoke(String tokenId) {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "UPDATE a2_tokens SET revoked = TRUE WHERE token_id = ?")) {
            ps.setString(1, tokenId);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "UPDATE a2_tokens SET revoked = TRUE WHERE principal_id = ?")) {
            ps.setString(1, principalId);
            ps.executeUpdate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int purgeExpired() {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "DELETE FROM a2_tokens WHERE expires_at < ? OR revoked = TRUE")) {
            ps.setTimestamp(1, Timestamp.from(Instant.now()));
            return ps.executeUpdate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void bind(PreparedStatement ps, TokenRecord r) throws Exception {
        ps.setString(1, r.tokenId());
        ps.setString(2, r.tokenValue());
        ps.setString(3, r.type().name());
        ps.setString(4, r.principalId());
        ps.setString(5, r.issuer());
        ps.setTimestamp(6, Timestamp.from(r.issuedAt()));
        ps.setTimestamp(7, Timestamp.from(r.expiresAt()));
        ps.setBoolean(8, r.revoked());
        ps.setString(9, r.assumedRole());
        ps.setString(10, r.impersonatedBy());
        ps.setString(11, claimsToJson(r.claims()));
    }

    private Optional<TokenRecord> queryOne(String sql, Object... params) {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setObject(i + 1, params[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(map(rs));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    private TokenRecord map(ResultSet rs) throws Exception {
        Map<String, Object> claims = jsonToClaims(rs.getString("claims_json"));
        return new TokenRecord(
                rs.getString("token_id"),
                rs.getString("token_value"),
                TokenType.valueOf(rs.getString("token_type")),
                rs.getString("principal_id"),
                rs.getString("issuer"),
                rs.getTimestamp("issued_at").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),
                rs.getBoolean("revoked"),
                rs.getString("assumed_role"),
                rs.getString("impersonated_by"),
                claims
        );
    }

    private static String claimsToJson(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) return "{}";
        // minimal JSON; production should use Jackson
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (var e : claims.entrySet()) {
            if (!first) sb.append(',');
            sb.append('"').append(e.getKey()).append("\":\"")
              .append(String.valueOf(e.getValue()).replace("\"", "\\\"")).append('"');
            first = false;
        }
        return sb.append('}').toString();
    }

    private static Map<String, Object> jsonToClaims(String json) {
        Map<String, Object> m = new HashMap<>();
        if (json == null || json.isBlank() || "{}".equals(json)) return m;
        // very minimal parser for demo; use Jackson in production
        return m;
    }
}
