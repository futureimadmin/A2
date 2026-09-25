package io.a2.core.store;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;
import io.a2.spi.model.StoredToken;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * JDBC-backed persistent TokenStore.
 *
 * Expected table (auto-create helper provided):
 *
 * <pre>
 * CREATE TABLE a2_tokens (
 *   token_id        VARCHAR(64) PRIMARY KEY,
 *   raw_token       VARCHAR(2048),
 *   token_type      VARCHAR(32),
 *   principal_id    VARCHAR(255) NOT NULL,
 *   protocol        VARCHAR(32),
 *   issued_at       TIMESTAMP NOT NULL,
 *   expires_at      TIMESTAMP,
 *   claims_json     CLOB,
 *   revoked         BOOLEAN DEFAULT FALSE,
 *   parent_token_id VARCHAR(64),
 *   audience        VARCHAR(255),
 *   session_name    VARCHAR(255)
 * );
 * CREATE INDEX idx_a2_tokens_principal ON a2_tokens(principal_id);
 * </pre>
 */
public class JdbcTokenStore implements TokenStore {

    private final DataSource dataSource;

    public JdbcTokenStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /** Creates the table if it does not exist (best-effort, vendor-neutral). */
    public void initSchema() throws SQLException {
        String ddl = """
            CREATE TABLE IF NOT EXISTS a2_tokens (
              token_id        VARCHAR(64) PRIMARY KEY,
              raw_token       VARCHAR(2048),
              token_type      VARCHAR(32),
              principal_id    VARCHAR(255) NOT NULL,
              protocol        VARCHAR(32),
              issued_at       TIMESTAMP NOT NULL,
              expires_at      TIMESTAMP,
              claims_json     VARCHAR(4000),
              revoked         BOOLEAN DEFAULT FALSE,
              parent_token_id VARCHAR(64),
              audience        VARCHAR(255),
              session_name    VARCHAR(255)
            )
            """;
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(ddl)) {
            ps.execute();
        }
    }

    @Override
    public void save(StoredToken token) {
        String sql = """
            MERGE INTO a2_tokens (token_id, raw_token, token_type, principal_id, protocol,
                                  issued_at, expires_at, claims_json, revoked,
                                  parent_token_id, audience, session_name)
            KEY (token_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
        // Fallback for databases without MERGE
        String insert = """
            INSERT INTO a2_tokens (token_id, raw_token, token_type, principal_id, protocol,
                                   issued_at, expires_at, claims_json, revoked,
                                   parent_token_id, audience, session_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
        try (Connection c = dataSource.getConnection()) {
            try (PreparedStatement ps = c.prepareStatement(insert)) {
                bind(ps, token);
                ps.executeUpdate();
            } catch (SQLException ex) {
                // try update
                String update = """
                    UPDATE a2_tokens SET raw_token=?, token_type=?, principal_id=?, protocol=?,
                           issued_at=?, expires_at=?, claims_json=?, revoked=?,
                           parent_token_id=?, audience=?, session_name=?
                    WHERE token_id=?
                    """;
                try (PreparedStatement ups = c.prepareStatement(update)) {
                    ups.setString(1, token.rawToken());
                    ups.setString(2, token.type() != null ? token.type().name() : null);
                    ups.setString(3, token.principalId());
                    ups.setString(4, token.protocol() != null ? token.protocol().name() : null);
                    ups.setTimestamp(5, Timestamp.from(token.issuedAt()));
                    ups.setTimestamp(6, token.expiresAt() != null ? Timestamp.from(token.expiresAt()) : null);
                    ups.setString(7, claimsToJson(token.claims()));
                    ups.setBoolean(8, token.revoked());
                    ups.setString(9, token.parentTokenId());
                    ups.setString(10, token.audience());
                    ups.setString(11, token.sessionName());
                    ups.setString(12, token.tokenId());
                    ups.executeUpdate();
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to save token", e);
        }
    }

    private void bind(PreparedStatement ps, StoredToken token) throws SQLException {
        ps.setString(1, token.tokenId());
        ps.setString(2, token.rawToken());
        ps.setString(3, token.type() != null ? token.type().name() : null);
        ps.setString(4, token.principalId());
        ps.setString(5, token.protocol() != null ? token.protocol().name() : null);
        ps.setTimestamp(6, Timestamp.from(token.issuedAt()));
        ps.setTimestamp(7, token.expiresAt() != null ? Timestamp.from(token.expiresAt()) : null);
        ps.setString(8, claimsToJson(token.claims()));
        ps.setBoolean(9, token.revoked());
        ps.setString(10, token.parentTokenId());
        ps.setString(11, token.audience());
        ps.setString(12, token.sessionName());
    }

    @Override
    public Optional<StoredToken> findById(String tokenId) {
        String sql = "SELECT * FROM a2_tokens WHERE token_id = ?";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, tokenId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(map(rs));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    @Override
    public Optional<StoredToken> findByRawToken(String rawToken) {
        String sql = "SELECT * FROM a2_tokens WHERE raw_token = ?";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, rawToken);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(map(rs));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    @Override
    public List<StoredToken> findByPrincipal(String principalId) {
        String sql = "SELECT * FROM a2_tokens WHERE principal_id = ?";
        return queryList(sql, principalId);
    }

    @Override
    public List<StoredToken> findByPrincipalAndType(String principalId, TokenType type) {
        String sql = "SELECT * FROM a2_tokens WHERE principal_id = ? AND token_type = ?";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, principalId);
            ps.setString(2, type.name());
            try (ResultSet rs = ps.executeQuery()) {
                List<StoredToken> list = new ArrayList<>();
                while (rs.next()) list.add(map(rs));
                return list;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void revoke(String tokenId) {
        String sql = "UPDATE a2_tokens SET revoked = TRUE WHERE token_id = ?";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, tokenId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void revokeAllForPrincipal(String principalId) {
        String sql = "UPDATE a2_tokens SET revoked = TRUE WHERE principal_id = ?";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, principalId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void revokeExpired(Instant before) {
        String sql = "UPDATE a2_tokens SET revoked = TRUE WHERE expires_at < ? AND revoked = FALSE";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setTimestamp(1, Timestamp.from(before));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private List<StoredToken> queryList(String sql, String principalId) {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, principalId);
            try (ResultSet rs = ps.executeQuery()) {
                List<StoredToken> list = new ArrayList<>();
                while (rs.next()) list.add(map(rs));
                return list;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private StoredToken map(ResultSet rs) throws SQLException {
        return StoredToken.builder()
                .tokenId(rs.getString("token_id"))
                .rawToken(rs.getString("raw_token"))
                .type(parseEnum(TokenType.class, rs.getString("token_type")))
                .principalId(rs.getString("principal_id"))
                .protocol(parseEnum(Protocol.class, rs.getString("protocol")))
                .issuedAt(rs.getTimestamp("issued_at") != null ? rs.getTimestamp("issued_at").toInstant() : null)
                .expiresAt(rs.getTimestamp("expires_at") != null ? rs.getTimestamp("expires_at").toInstant() : null)
                .claims(jsonToClaims(rs.getString("claims_json")))
                .revoked(rs.getBoolean("revoked"))
                .parentTokenId(rs.getString("parent_token_id"))
                .audience(rs.getString("audience"))
                .sessionName(rs.getString("session_name"))
                .build();
    }

    private static <E extends Enum<E>> E parseEnum(Class<E> type, String name) {
        if (name == null) return null;
        try { return Enum.valueOf(type, name); } catch (Exception e) { return null; }
    }

    // Minimal JSON helpers (avoid hard dependency on Jackson in core)
    private static String claimsToJson(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) return "{}";
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : claims.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(escape(e.getKey())).append("\":\"")
              .append(escape(String.valueOf(e.getValue()))).append('"');
        }
        return sb.append('}').toString();
    }

    private static Map<String, Object> jsonToClaims(String json) {
        if (json == null || json.isBlank() || "{}".equals(json)) return Collections.emptyMap();
        Map<String, Object> map = new HashMap<>();
        // very simple parser for flat string maps
        String body = json.trim();
        if (body.startsWith("{")) body = body.substring(1);
        if (body.endsWith("}")) body = body.substring(0, body.length() - 1);
        for (String part : body.split(",")) {
            String[] kv = part.split(":", 2);
            if (kv.length == 2) {
                String k = kv[0].trim().replaceAll("^\"|\"$", "");
                String v = kv[1].trim().replaceAll("^\"|\"$", "");
                map.put(k, v);
            }
        }
        return map;
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
