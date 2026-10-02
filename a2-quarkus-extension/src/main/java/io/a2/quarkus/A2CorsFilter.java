package io.a2.quarkus;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION - 10)
public class A2CorsFilter implements ContainerRequestFilter, ContainerResponseFilter {

    @ConfigProperty(name = "a2.cors.enabled", defaultValue = "true")
    boolean enabled;

    @ConfigProperty(name = "a2.cors.origins", defaultValue = "*")
    String origins;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (!enabled) return;
        if ("OPTIONS".equalsIgnoreCase(requestContext.getMethod())) {
            requestContext.abortWith(Response.ok()
                    .header("Access-Control-Allow-Origin", resolveOrigin(requestContext))
                    .header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD")
                    .header("Access-Control-Allow-Headers",
                            "Authorization,Content-Type,X-API-Key,X-A2-SSO-Provider,X-Merchant-Id")
                    .header("Access-Control-Max-Age", "3600")
                    .build());
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        if (!enabled) return;
        if (!responseContext.getHeaders().containsKey("Access-Control-Allow-Origin")) {
            responseContext.getHeaders().putSingle(
                    "Access-Control-Allow-Origin", resolveOrigin(requestContext));
        }
        responseContext.getHeaders().putSingle("Access-Control-Expose-Headers",
                "Authorization,WWW-Authenticate,X-A2-SSO-Provider");
    }

    private String resolveOrigin(ContainerRequestContext ctx) {
        if (origins == null || origins.isBlank() || "*".equals(origins.trim())) {
            String req = ctx.getHeaderString("Origin");
            return req != null ? req : "*";
        }
        return origins.split(",")[0].trim();
    }
}
