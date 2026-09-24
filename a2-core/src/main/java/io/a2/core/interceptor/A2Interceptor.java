package io.a2.core.interceptor;

import io.a2.annotations.A2Authorize;
import io.a2.annotations.A2Protected;
import io.a2.annotations.A2Revoke;
import io.a2.annotations.A2Rotate;
import io.a2.annotations.A2Token;
import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.A2Runtime;
import io.a2.core.DefaultSecurityContext;
import io.a2.spi.Principal;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.SecurityContext;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.RevokeRequest;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Core interceptor that enforces A2 annotations.
 * Framework integrations (Spring AOP, CDI, Quarkus, etc.) should call this.
 */
public class A2Interceptor {

    private final A2Runtime runtime = A2Runtime.get();

    /**
     * Call before the target method.
     * Returns true if the call is allowed to proceed.
     */
    public boolean before(Object target, Method method, Object[] args) {
        A2Protected protectedAnn = findProtected(method, target.getClass());
        if (protectedAnn == null) {
            return true; // not protected
        }

        SecurityContext ctx = runtime.currentContext();
        if (!ctx.isAuthenticated() && !protectedAnn.allowAnonymous()) {
            throw new SecurityException("Authentication required");
        }

        // Protocol check
        if (protectedAnn.protocols().length > 0) {
            boolean ok = Arrays.stream(protectedAnn.protocols())
                    .anyMatch(p -> p == ctx.protocol());
            if (!ok) {
                throw new SecurityException("Protocol not allowed: " + ctx.protocol());
            }
        }

        // Role / permission check from @A2Protected
        checkRolesAndPermissions(ctx, protectedAnn.roles(), protectedAnn.permissions(),
                protectedAnn.requireAllRoles());

        // Additional @A2Authorize
        A2Authorize authz = method.getAnnotation(A2Authorize.class);
        if (authz == null) {
            authz = target.getClass().getAnnotation(A2Authorize.class);
        }
        if (authz != null) {
            checkAuthorization(ctx, authz);
        }

        return true;
    }

    /**
     * Call after successful method execution to handle @A2Token / @A2Rotate / @A2Revoke.
     */
    public void afterSuccess(Object target, Method method, Object result) {
        A2Token tokenAnn = method.getAnnotation(A2Token.class);
        if (tokenAnn != null) {
            handleToken(tokenAnn);
        }

        A2Rotate rotate = method.getAnnotation(A2Rotate.class);
        if (rotate != null) {
            handleRotate(rotate);
        }

        A2Revoke revoke = method.getAnnotation(A2Revoke.class);
        if (revoke != null) {
            handleRevoke(revoke);
        }
    }

    private A2Protected findProtected(Method method, Class<?> clazz) {
        A2Protected m = method.getAnnotation(A2Protected.class);
        if (m != null) return m;
        return clazz.getAnnotation(A2Protected.class);
    }

    private void checkRolesAndPermissions(SecurityContext ctx, String[] roles,
                                          String[] permissions, boolean requireAll) {
        if (roles.length == 0 && permissions.length == 0) return;

        Set<String> requiredRoles = new HashSet<>(Arrays.asList(roles));
        Set<String> requiredPerms = new HashSet<>(Arrays.asList(permissions));

        if (requireAll) {
            if (!ctx.roles().containsAll(requiredRoles)) {
                throw new SecurityException("Missing required roles");
            }
            if (!ctx.permissions().containsAll(requiredPerms)) {
                throw new SecurityException("Missing required permissions");
            }
        } else {
            boolean roleOk = requiredRoles.isEmpty() ||
                    requiredRoles.stream().anyMatch(ctx::hasRole);
            boolean permOk = requiredPerms.isEmpty() ||
                    requiredPerms.stream().anyMatch(ctx::hasPermission);
            if (!roleOk && !permOk) {
                throw new SecurityException("Insufficient privileges");
            }
        }
    }

    private void checkAuthorization(SecurityContext ctx, A2Authorize authz) {
        AuthorizationContext ac = new AuthorizationContext(
                ctx,
                Set.of(authz.roles()),
                Set.of(authz.permissions()),
                authz.requireAll(),
                authz.policy()
        );

        // Prefer protocol-specific authorize if available
        Optional<ProtocolProvider> provider = runtime.provider(ctx.protocol());
        if (provider.isPresent()) {
            if (!provider.get().authorize(ac)) {
                throw new SecurityException("Authorization denied by provider");
            }
        } else {
            // Fallback to simple role/permission check
            checkRolesAndPermissions(ctx, authz.roles(), authz.permissions(), authz.requireAll());
        }
    }

    private void handleToken(A2Token ann) {
        SecurityContext ctx = runtime.currentContext();
        String principalId = ctx.principal().map(Principal::getId).orElse(null);
        if (principalId == null) return;

        TokenRequest req = TokenRequest.builder()
                .type(ann.type())
                .principalId(principalId)
                .ttlSeconds(ann.ttlSeconds())
                .scopes(ann.scopes())
                .protocol(ctx.protocol())
                .build();

        TokenResult result = runtime.tokenService().issue(req);
        if (ann.rotate() && result.isSuccess()) {
            // rotation already handled by TokenService if configured
        }
    }

    private void handleRotate(A2Rotate ann) {
        SecurityContext ctx = runtime.currentContext();
        String principalId = ctx.principal().map(Principal::getId).orElse(null);
        String existing = ctx.tokenId().orElse(null);
        if (principalId == null) return;

        for (TokenType type : ann.types()) {
            TokenRequest req = TokenRequest.builder()
                    .type(type)
                    .principalId(principalId)
                    .existingToken(existing)
                    .protocol(ctx.protocol())
                    .build();
            runtime.tokenService().rotate(req);
        }
    }

    private void handleRevoke(A2Revoke ann) {
        SecurityContext ctx = runtime.currentContext();
        String principalId = ctx.principal().map(Principal::getId).orElse(null);
        String tokenId = ctx.tokenId().orElse(null);

        if (ann.allForPrincipal() && principalId != null) {
            runtime.tokenService().revokeAllForPrincipal(principalId);
        } else if (tokenId != null) {
            runtime.tokenService().revoke(tokenId);
        }
    }
}
