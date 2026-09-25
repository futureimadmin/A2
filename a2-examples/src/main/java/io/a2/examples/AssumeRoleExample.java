package io.a2.examples;

import io.a2.annotations.A2AssumeRole;
import io.a2.annotations.A2Impersonate;
import io.a2.annotations.A2Protected;
import io.a2.annotations.A2ServiceCredential;
import io.a2.annotations.Protocol;
import io.a2.core.A2Runtime;
import io.a2.core.DefaultImpersonationService;
import io.a2.core.DefaultSecurityContext;
import io.a2.core.PersistentTokenService;
import io.a2.core.SimplePrincipal;
import io.a2.core.store.InMemoryTokenStore;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.spi.ImpersonationService;
import io.a2.spi.TokenStore;
import io.a2.spi.model.TokenResult;

/**
 * Demonstrates:
 * - Service-to-service temporary credentials (1 hour)
 * - AssumeRole
 * - User Impersonation
 */
public class AssumeRoleExample {

    public static void main(String[] args) {
        TokenStore store = new InMemoryTokenStore();
        JwtProtocolProvider jwt = new JwtProtocolProvider(
                "a2-dev-secret-change-me-must-be-at-least-32-bytes-long!!",
                "https://a2.local",
                store
        );

        A2Runtime runtime = A2Runtime.get();
        runtime.register(jwt);
        runtime.setTokenService(new PersistentTokenService(store));

        ImpersonationService imp = new DefaultImpersonationService(runtime.tokenService(), store);

        // 1. Service identity
        SimplePrincipal serviceA = SimplePrincipal.of("service-order", "service-order", "service");
        runtime.setContext(DefaultSecurityContext.of(serviceA, Protocol.JWT));

        // 2. Assume a role for S2S call (max 1 hour)
        TokenResult assumed = imp.assumeRole(serviceA, "billing-admin", 3600, "order-to-billing");
        System.out.println("Assumed-role token (1h): " + assumed.token().orElse("?"));
        System.out.println("Expires: " + assumed.expiresAt().orElse(null));

        // 3. Impersonation (support agent)
        SimplePrincipal agent = new SimplePrincipal("agent-42", "Alice Agent",
                java.util.Set.of("admin", "support"),
                java.util.Set.of("impersonate"),
                java.util.Map.of());
        runtime.setContext(DefaultSecurityContext.of(agent, Protocol.JWT));

        TokenResult impToken = imp.impersonate(agent, "customer-777", 1800, "support-ticket-12345");
        System.out.println("Impersonation token: " + impToken.token().orElse("?"));
        System.out.println("Claims contain impersonated_by: " +
                impToken.claims().get("impersonated_by"));

        // 4. Service credential helper
        TokenResult s2s = runtime.tokenService().issue(
                io.a2.spi.model.TokenRequest.builder()
                        .type(io.a2.annotations.TokenType.ACCESS)
                        .principalId("service-order")
                        .ttlSeconds(3600)
                        .scopes("s2s", "billing:write")
                        .claims(java.util.Map.of("token_use", "service_credential", "aud", "billing-service"))
                        .protocol(Protocol.JWT)
                        .build()
        );
        System.out.println("S2S 1h credential: " + s2s.token().orElse("?"));
    }

    // Example service methods using the new annotations
    @A2Protected(protocols = Protocol.JWT)
    public static class BillingClient {

        @A2AssumeRole(role = "billing-admin", ttlSeconds = 3600, sessionName = "order-flow")
        public void chargeCustomer(String orderId) {
            // runtime issues assumed-role token before method body
        }

        @A2ServiceCredential(audience = "billing-service", scopes = {"billing:write"}, ttlSeconds = 3600)
        public String obtainS2SToken() {
            return "token-placeholder";
        }
    }

    public static class SupportDesk {

        @A2Impersonate(targetPrincipalParam = "customerId", ttlSeconds = 1800)
        public void viewAsCustomer(String customerId, String reason) {
            // runtime checks permission + issues impersonation token
        }
    }
}
