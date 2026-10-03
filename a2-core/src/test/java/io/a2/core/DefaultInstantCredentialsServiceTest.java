package io.a2.core;

import io.a2.annotations.InstantMode;
import io.a2.annotations.TokenType;
import io.a2.core.store.InMemoryTokenStore;
import io.a2.spi.TokenService;
import io.a2.spi.TokenStore;
import io.a2.spi.model.InstantCredentialsRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class DefaultInstantCredentialsServiceTest {

    private TokenStore store;
    private DefaultInstantCredentialsService service;

    @BeforeEach
    void setUp() {
        store = new InMemoryTokenStore();
        TokenService tokens = new TokenService() {
            @Override
            public TokenResult issue(TokenRequest request) {
                String id = UUID.randomUUID().toString();
                String raw = "tok-" + id;
                Instant exp = Instant.now().plusSeconds(
                        request.ttlSeconds() > 0 ? request.ttlSeconds() : 3600);
                return TokenResult.success(raw, id,
                        request.type() != null ? request.type() : TokenType.TEMPORARY,
                        exp, request.claims());
            }

            @Override
            public TokenResult rotate(TokenRequest request) {
                return TokenResult.failure("not used");
            }

            @Override
            public void revoke(String tokenId) { }

            @Override
            public void revokeAllForPrincipal(String principalId) { }

            @Override
            public java.util.Optional<TokenResult> introspect(String token) {
                return java.util.Optional.empty();
            }
        };
        service = new DefaultInstantCredentialsService(tokens, store);
    }

    @Test
    void serviceModeIssuesTemporaryToken() {
        InstantCredentialsRequest req = InstantCredentialsRequest.builder(InstantMode.SERVICE)
                .callerPrincipalId("svc-a")
                .audience("payment-service")
                .scopes("payment:charge")
                .ttlSeconds(3600)
                .build();
        TokenResult r = service.issue(req);
        assertTrue(r.isSuccess());
        assertTrue(r.token().isPresent());
        assertEquals(TokenType.TEMPORARY, r.type().orElse(null));
    }

    @Test
    void ttlIsHardCappedAtOneHour() {
        InstantCredentialsRequest req = InstantCredentialsRequest.builder(InstantMode.SERVICE)
                .callerPrincipalId("svc-a")
                .audience("x")
                .ttlSeconds(86_400)
                .build();
        assertEquals(3600, req.ttlSeconds());
        TokenResult r = service.issue(req);
        assertTrue(r.isSuccess());
        assertTrue(r.expiresAt().isPresent());
        long seconds = r.expiresAt().get().getEpochSecond() - Instant.now().getEpochSecond();
        assertTrue(seconds <= 3600 + 5, "TTL must be <= 1h, was " + seconds);
    }

    @Test
    void assumeRoleRequiresRole() {
        InstantCredentialsRequest req = InstantCredentialsRequest.builder(InstantMode.ASSUME_ROLE)
                .callerPrincipalId("user-1")
                .ttlSeconds(1800)
                .build();
        TokenResult r = service.issue(req);
        assertFalse(r.isSuccess());
        assertTrue(r.error().orElse("").contains("role"));
    }

    @Test
    void assumeRoleSucceeds() {
        InstantCredentialsRequest req = InstantCredentialsRequest.builder(InstantMode.ASSUME_ROLE)
                .callerPrincipalId("user-1")
                .role("billing-admin")
                .sessionName("nightly")
                .ttlSeconds(1800)
                .build();
        TokenResult r = service.issue(req);
        assertTrue(r.isSuccess(), r.error().orElse("ok"));
        assertEquals(TokenType.ASSUMED_ROLE, r.type().orElse(null));
    }

    @Test
    void impersonateRequiresTarget() {
        InstantCredentialsRequest req = InstantCredentialsRequest.builder(InstantMode.IMPERSONATE)
                .callerPrincipalId("source-sa")
                .reason("batch")
                .build();
        TokenResult r = service.issue(req);
        assertFalse(r.isSuccess());
        assertTrue(r.error().orElse("").toLowerCase().contains("target"));
    }

    @Test
    void impersonateSourceToTarget() {
        InstantCredentialsRequest req = InstantCredentialsRequest.builder(InstantMode.IMPERSONATE)
                .callerPrincipalId("source@project.iam.gserviceaccount.com")
                .targetPrincipalId("jobs@project.iam.gserviceaccount.com")
                .reason("batch-job")
                .ttlSeconds(3600)
                .build();
        TokenResult r = service.issue(req);
        assertTrue(r.isSuccess(), r.error().orElse("ok"));
        assertEquals(TokenType.IMPERSONATION, r.type().orElse(null));
    }
}
