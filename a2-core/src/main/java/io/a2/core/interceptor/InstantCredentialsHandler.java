package io.a2.core.interceptor;

import io.a2.annotations.A2InstantCredentials;
import io.a2.core.A2Runtime;
import io.a2.core.DefaultInstantCredentialsService;
import io.a2.core.DefaultSecurityContext;
import io.a2.core.store.InMemoryTokenStore;
import io.a2.spi.InstantCredentialsService;
import io.a2.spi.Principal;
import io.a2.spi.SecurityContext;
import io.a2.spi.model.InstantCredentialsRequest;
import io.a2.spi.model.TokenResult;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.HashMap;
import java.util.Map;

/** Handles {@link A2InstantCredentials} — issues <=1h temp credentials. */
public final class InstantCredentialsHandler {

    private InstantCredentialsService service;

    public InstantCredentialsHandler() {}

    public InstantCredentialsHandler(InstantCredentialsService service) {
        this.service = service;
    }

    public void setService(InstantCredentialsService service) {
        this.service = service;
    }

    private InstantCredentialsService svc(A2Runtime runtime) {
        if (service == null) {
            service = new DefaultInstantCredentialsService(
                    runtime.tokenService(), new InMemoryTokenStore());
        }
        return service;
    }

    public TokenResult handle(A2InstantCredentials ann, Method method, Object[] args,
                              SecurityContext ctx, A2Runtime runtime) {
        Principal caller = ctx.principal().orElseThrow(
                () -> new SecurityException("Instant credentials require authenticated caller"));

        String target = ann.targetPrincipal();
        if (target == null || target.isBlank()) {
            target = resolveParam(method, args, ann.targetPrincipalParam());
        }
        String reason = resolveParam(method, args, "reason");
        if (reason == null || reason.isBlank()) {
            reason = ann.reason();
        }

        InstantCredentialsRequest req = InstantCredentialsRequest.builder(ann.mode())
                .callerPrincipalId(caller.getId())
                .role(ann.role())
                .targetPrincipalId(target != null ? target : "")
                .audience(ann.audience())
                .scopes(ann.scopes())
                .sessionName(ann.sessionName())
                .reason(reason != null ? reason : "")
                .ttlSeconds(ann.ttlSeconds())
                .build();

        TokenResult tr = svc(runtime).issue(req);
        if (!tr.isSuccess()) {
            throw new SecurityException("Instant credentials failed (" + ann.mode() + "): "
                    + tr.error().orElse("unknown"));
        }

        if (ann.attachToContext()) {
            Map<String, Object> claims = new HashMap<>(ctx.claims());
            claims.put("a2.instant.mode", ann.mode().name());
            claims.put("a2.instant.token_id", tr.tokenId().orElse(""));
            tr.token().ifPresent(t -> claims.put("a2.instant.token", t));
            tr.expiresAt().ifPresent(e -> claims.put("a2.instant.expires_at", e.toString()));
            runtime.setContext(new DefaultSecurityContext(
                    caller, ctx.protocol(), ctx.roles(), ctx.permissions(), claims,
                    tr.tokenId().orElse(ctx.tokenId().orElse(null))));
        }
        return tr;
    }

    private static String resolveParam(Method method, Object[] args, String name) {
        Parameter[] params = method.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (params[i].getName().equals(name) && args[i] != null) {
                return String.valueOf(args[i]);
            }
        }
        for (Object a : args) {
            if (a instanceof String) {
                return (String) a;
            }
        }
        return null;
    }
}
