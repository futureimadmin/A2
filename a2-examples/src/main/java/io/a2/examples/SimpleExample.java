package io.a2.examples;

import io.a2.annotations.A2Authorize;
import io.a2.annotations.A2Protected;
import io.a2.annotations.A2Revoke;
import io.a2.annotations.A2Token;
import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.A2Runtime;
import io.a2.core.DefaultSecurityContext;
import io.a2.core.DefaultTokenService;
import io.a2.core.SimplePrincipal;
import io.a2.core.interceptor.A2Interceptor;
import io.a2.provider.apikey.ApiKeyProtocolProvider;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.lang.reflect.Method;

/**
 * Minimal standalone example showing annotation-driven AuthN / AuthZ / token lifecycle.
 */
public class SimpleExample {

    public static void main(String[] args) throws Exception {
        // 1. Bootstrap
        A2Runtime runtime = A2Runtime.get();
        runtime.register(new JwtProtocolProvider());
        runtime.register(new ApiKeyProtocolProvider());
        runtime.setTokenService(new DefaultTokenService());

        A2Interceptor interceptor = new A2Interceptor();
        OrderService service = new OrderService();

        // 2. Simulate login → obtain JWT
        TokenResult issued = runtime.tokenService().issue(TokenRequest.builder()
                .type(TokenType.ACCESS)
                .principalId("alice")
                .protocol(Protocol.JWT)
                .ttlSeconds(3600)
                .claims(java.util.Map.of("roles", "user,admin"))
                .build());
        System.out.println("Issued token: " + issued.token().orElse("?"));

        // 3. Authenticate with the token
        AuthResult auth = runtime.authenticate(AuthRequest.builder()
                .protocol(Protocol.JWT)
                .credentials(issued.token().orElseThrow())
                .build());
        if (!auth.isSuccess()) {
            System.err.println("Auth failed: " + auth.error().orElse("unknown"));
            return;
        }
        runtime.setContext(DefaultSecurityContext.of(auth.principal().orElseThrow(), Protocol.JWT));

        // 4. Call protected method via interceptor
        Method getOrder = OrderService.class.getMethod("getOrder", String.class);
        interceptor.before(service, getOrder, new Object[]{"ORD-1"});
        String result = service.getOrder("ORD-1");
        System.out.println("Result: " + result);

        // 5. Logout → revoke
        Method logout = OrderService.class.getMethod("logout");
        interceptor.before(service, logout, new Object[0]);
        service.logout();
        interceptor.afterSuccess(service, logout, null);
        System.out.println("Logged out — tokens revoked.");
    }

    @A2Protected(roles = {"user"}, protocols = {Protocol.JWT, Protocol.API_KEY})
    public static class OrderService {

        @A2Authorize(permissions = {"order:read"})
        public String getOrder(String id) {
            return "Order " + id + " for " +
                    A2Runtime.get().currentContext().principal().map(p -> p.getName()).orElse("?");
        }

        @A2Token(type = TokenType.ACCESS, rotate = true)
        public void refreshSession() {
            // token rotation handled by interceptor
        }

        @A2Revoke(allForPrincipal = true, reason = "logout")
        public void logout() {
            System.out.println("Performing logout...");
        }
    }
}
