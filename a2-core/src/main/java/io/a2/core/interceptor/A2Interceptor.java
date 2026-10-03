package io.a2.core.interceptor;

import io.a2.annotations.A2AssumeRole;
import io.a2.annotations.A2Authorize;
import io.a2.annotations.A2Impersonate;
import io.a2.annotations.A2InstantCredentials;
import io.a2.annotations.A2Protected;
import io.a2.annotations.A2Revoke;
import io.a2.annotations.A2Rotate;
import io.a2.annotations.A2ServiceCredential;
import io.a2.annotations.A2Token;
import io.a2.annotations.TokenType;
import io.a2.core.A2Runtime;
import io.a2.core.DefaultImpersonationService;
import io.a2.spi.ImpersonationService;
import io.a2.spi.Principal;
import io.a2.spi.ProtocolProvider;
import io.a2.spi.SecurityContext;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.TokenRequest;
import io.a2.spi.model.TokenResult;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Core interceptor: AuthZ, AssumeRole, Impersonation, Service + Instant Credentials. */
public class A2Interceptor {

    private final A2Runtime runtime = A2Runtime.get();
    private ImpersonationService impersonationService;
    private final InstantCredentialsHandler instantHandler = new InstantCredentialsHandler();

    public void setImpersonationService(ImpersonationService svc) {
        this.impersonationService = svc;
    }

    public void setInstantCredentialsService(io.a2.spi.InstantCredentialsService svc) {
        this.instantHandler.setService(svc);
    }

    private ImpersonationService imp() {
        if (impersonationService == null) {
            impersonationService = new DefaultImpersonationService(
                    runtime.tokenService(), null);
        }
        return impersonationService;
    }

    public boolean before(Object target, Method method, Object[] args) {
        A2Protected protectedAnn = findProtected(method, target.getClass());
        if (protectedAnn == null
                && method.getAnnotation(A2Authorize.class) == null
                && method.getAnnotation(A2AssumeRole.class) == null
                && method.getAnnotation(A2Impersonate.class) == null
                && method.getAnnotation(A2ServiceCredential.class) == null
                && method.getAnnotation(A2InstantCredentials.class) == null) {
            return true;
        }

        SecurityContext ctx = runtime.currentContext();

        if (protectedAnn != null) {
            if (!ctx.isAuthenticated() && !protectedAnn.allowAnonymous()) {
                throw new SecurityException("Authentication required");
            }
            if (protectedAnn.protocols().length > 0) {
                boolean ok = Arrays.stream(protectedAnn.protocols())
                        .anyMatch(p -> p == ctx.protocol());
                if (!ok) {
                    throw new SecurityException("Protocol not allowed: " + ctx.protocol());
                }
            }
            checkRolesAndPermissions(ctx, protectedAnn.roles(), protectedAnn.permissions(),
                    protectedAnn.requireAllRoles());
        }

        A2Authorize authz = method.getAnnotation(A2Authorize.class);
        if (authz == null) {
            authz = target.getClass().getAnnotation(A2Authorize.class);
        }
        if (authz != null) {
            checkAuthorization(ctx, authz);
        }

        A2AssumeRole assume = method.getAnnotation(A2AssumeRole.class);
        if (assume != null) {
            Principal caller = ctx.principal().orElseThrow(
                    () -> new SecurityException("AssumeRole requires authenticated caller"));
            TokenResult tr = imp().assumeRole(caller, assume.role(), assume.ttlSeconds(),
                    assume.sessionName());
            if (!tr.isSuccess()) {
                throw new SecurityException("AssumeRole failed: " + tr.error().orElse("unknown"));
            }
        }

        A2Impersonate impAnn = method.getAnnotation(A2Impersonate.class);
        if (impAnn != null) {
            Principal caller = ctx.principal().orElseThrow(
                    () -> new SecurityException("Impersonation requires authenticated caller"));
            String targetId = resolveParam(method, args, impAnn.targetPrincipalParam());
            String reason = resolveParam(method, args, "reason");
            if (reason == null || reason.isBlank()) {
                reason = impAnn.reason();
            }
            TokenResult tr = imp().impersonate(caller, targetId, impAnn.ttlSeconds(), reason);
            if (!tr.isSuccess()) {
                throw new SecurityException("Impersonation failed: " + tr.error().orElse("unknown"));
            }
        }

        A2InstantCredentials instantAnn = method.getAnnotation(A2InstantCredentials.class);
        if (instantAnn != null) {
            instantHandler.handle(instantAnn, method, args, ctx, runtime);
        }

        return true;
    }

    public void afterSuccess(Object target, Method method, Object result) {
        A2Token tokenAnn = method.getAnnotation(A2Token.class);
        if (tokenAnn != null) handleToken(tokenAnn);
        A2ServiceCredential s2s = method.getAnnotation(A2ServiceCredential.class);
        if (s2s != null) handleServiceCredential(s2s);
        A2Rotate rotate = method.getAnnotation(A2Rotate.class);
        if (rotate != null) handleRotate(rotate);
        A2Revoke revoke = method.getAnnotation(A2Revoke.class);
        if (revoke != null) handleRevoke(revoke);
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
            if (!requiredRoles.isEmpty() && !ctx.roles().containsAll(requiredRoles)) {
                throw new SecurityException("Missing required roles");
            }
            if (!requiredPerms.isEmpty() && !ctx.permissions().containsAll(requiredPerms)) {
                throw new SecurityException("Missing required permissions");
            }
        } else {
            // Non-empty role list: at least one required role must match.
            // Non-empty permission list: at least one required permission must match.
            // Both lists non-empty → both categories must pass (AND across categories, OR within).
            boolean roleOk = requiredRoles.isEmpty()
                    || requiredRoles.stream().anyMatch(ctx::hasRole);
            boolean permOk = requiredPerms.isEmpty()
                    || requiredPerms.stream().anyMatch(ctx::hasPermission);
            if (!roleOk || !permOk) {
                throw new SecurityException("Insufficient privileges");
            }
        }
    }

    private void checkAuthorization(SecurityContext ctx, A2Authorize authz) {
        AuthorizationContext ac = new AuthorizationContext(
                ctx, Set.of(authz.roles()), Set.of(authz.permissions()),
                authz.requireAll(), authz.policy());
        Optional<ProtocolProvider> provider = runtime.provider(ctx.protocol());
        if (provider.isPresent()) {
            if (!provider.get().authorize(ac))
                throw new SecurityException("Authorization denied by provider");
        } else {
            checkRolesAndPermissions(ctx, authz.roles(), authz.permissions(), authz.requireAll());
        }
    }

    private void handleToken(A2Token ann) {
        SecurityContext ctx = runtime.currentContext();
        String principalId = ctx.principal().map(Principal::getId).orElse(null);
        if (principalId == null) return;
        runtime.tokenService().issue(TokenRequest.builder()
                .type(ann.type()).principalId(principalId).ttlSeconds(ann.ttlSeconds())
                .scopes(ann.scopes()).protocol(ctx.protocol()).build());
    }

    private void handleServiceCredential(A2ServiceCredential ann) {
        SecurityContext ctx = runtime.currentContext();
        String principalId = ctx.principal().map(Principal::getId).orElse(null);
        if (principalId == null) return;
        long ttl = Math.min(ann.ttlSeconds() > 0 ? ann.ttlSeconds() : 3600, 3600);
        runtime.tokenService().issue(TokenRequest.builder()
                .type(TokenType.ACCESS).principalId(principalId).ttlSeconds(ttl)
                .scopes(ann.scopes())
                .claims(Map.of("token_use", "service_credential", "aud", ann.audience()))
                .protocol(ctx.protocol()).build());
    }

    private void handleRotate(A2Rotate ann) {
        SecurityContext ctx = runtime.currentContext();
        String principalId = ctx.principal().map(Principal::getId).orElse(null);
        String existing = ctx.tokenId().orElse(null);
        if (principalId == null) return;
        for (TokenType type : ann.types()) {
            runtime.tokenService().rotate(TokenRequest.builder()
                    .type(type).principalId(principalId).existingToken(existing)
                    .protocol(ctx.protocol()).build());
        }
    }

    private void handleRevoke(A2Revoke ann) {
        SecurityContext ctx = runtime.currentContext();
        String principalId = ctx.principal().map(Principal::getId).orElse(null);
        String tokenId = ctx.tokenId().orElse(null);
        if (ann.allForPrincipal() && principalId != null)
            runtime.tokenService().revokeAllForPrincipal(principalId);
        else if (tokenId != null)
            runtime.tokenService().revoke(tokenId);
    }

    private String resolveParam(Method method, Object[] args, String name) {
        Parameter[] params = method.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (params[i].getName().equals(name) && args[i] != null)
                return String.valueOf(args[i]);
        }
        for (Object a : args) {
            if (a instanceof String) return (String) a;
        }
        return null;
    }
}
