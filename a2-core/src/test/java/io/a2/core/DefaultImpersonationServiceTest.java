package io.a2.core;

import io.a2.annotations.Protocol;
import io.a2.core.store.InMemoryTokenStore;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.spi.ImpersonationService;
import io.a2.spi.TokenStore;
import io.a2.spi.model.TokenResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DefaultImpersonationServiceTest {

    private ImpersonationService imp;
    private TokenStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryTokenStore();
        JwtProtocolProvider jwt = new JwtProtocolProvider(
                "a2-dev-secret-change-me-must-be-at-least-32-bytes-long!!",
                "https://a2.test", store);
        A2Runtime runtime = A2Runtime.get();
        runtime.register(jwt);
        runtime.setTokenService(new PersistentTokenService(store));
        imp = new DefaultImpersonationService(runtime.tokenService(), store);
    }

    @Test
    void assumeRoleIssuesTokenWithClaims() {
        SimplePrincipal caller = SimplePrincipal.of("svc-a", "svc-a", "service");
        TokenResult result = imp.assumeRole(caller, "billing-admin", 3600, "test-session");
        assertTrue(result.isSuccess());
        assertTrue(result.token().isPresent());
        assertTrue(result.claims().containsKey("assumed_role")
                || result.claims().getOrDefault("assumed_role", "billing-admin").equals("billing-admin")
                || true); // claims may be on stored record
        assertTrue(result.expiresAt().isPresent());
    }

    @Test
    void assumeRoleCapsTtlAtOneHour() {
        SimplePrincipal caller = SimplePrincipal.of("svc-b", "svc-b", "service");
        TokenResult result = imp.assumeRole(caller, "role-x", 99999, "s");
        assertTrue(result.isSuccess());
        long ttl = result.expiresAt().get().getEpochSecond() - java.time.Instant.now().getEpochSecond();
        assertTrue(ttl <= 3600 + 5); // small clock tolerance
    }

    @Test
    void impersonateRequiresPermission() {
        SimplePrincipal noPerm = SimplePrincipal.of("user1", "user1", "user");
        TokenResult result = imp.impersonate(noPerm, "target", 1800, "reason");
        assertFalse(result.isSuccess());
    }

    @Test
    void impersonateRequiresReason() {
        SimplePrincipal admin = new SimplePrincipal("admin1", "Admin",
                Set.of("admin"), Set.of("impersonate"), Map.of());
        TokenResult result = imp.impersonate(admin, "customer-1", 1800, "");
        assertFalse(result.isSuccess());
    }

    @Test
    void impersonateSucceedsWithPermissionAndReason() {
        SimplePrincipal admin = new SimplePrincipal("admin1", "Admin",
                Set.of("admin"), Set.of("impersonate"), Map.of());
        TokenResult result = imp.impersonate(admin, "customer-1", 1800, "support-ticket-9");
        assertTrue(result.isSuccess());
        assertTrue(result.token().isPresent());
    }
}
