package io.a2.core;

import io.a2.core.store.InMemoryTokenStore;
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

    @BeforeEach
    void setUp() {
        TokenStore store = new InMemoryTokenStore();
        DefaultTokenService tokenService = new DefaultTokenService();
        A2Runtime.get().setTokenService(tokenService);
        imp = new DefaultImpersonationService(tokenService, store);
    }

    @Test
    void assumeRoleIssuesToken() {
        SimplePrincipal caller = SimplePrincipal.of("svc-a", "svc-a", "service");
        TokenResult result = imp.assumeRole(caller, "billing-admin", 3600, "test-session");
        assertTrue(result.isSuccess(), () -> result.error().orElse("unknown"));
        assertTrue(result.token().isPresent());
        assertTrue(result.expiresAt().isPresent());
    }

    @Test
    void assumeRoleCapsTtlAtOneHour() {
        SimplePrincipal caller = SimplePrincipal.of("svc-b", "svc-b", "service");
        TokenResult result = imp.assumeRole(caller, "role-x", 99999, "s");
        assertTrue(result.isSuccess());
        long ttl = result.expiresAt().get().getEpochSecond() - java.time.Instant.now().getEpochSecond();
        assertTrue(ttl <= 3600 + 5);
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
        assertTrue(result.isSuccess(), () -> result.error().orElse("unknown"));
        assertTrue(result.token().isPresent());
    }

    @Test
    void nullCallerFails() {
        assertFalse(imp.assumeRole(null, "role", 3600, "s").isSuccess());
        assertFalse(imp.impersonate(null, "t", 1800, "r").isSuccess());
    }
}
