package io.a2.quarkus;

import io.a2.core.auth.RequestAuthenticator;
import io.a2.core.exception.A2AuthenticationException;
import io.a2.core.exception.A2SecurityException;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION)
public class A2AuthFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private final RequestAuthenticator authenticator = new RequestAuthenticator();

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if ("OPTIONS".equalsIgnoreCase(requestContext.getMethod())) {
            return;
        }
        try {
            authenticator.authenticate(name -> requestContext.getHeaderString(name), false);
        } catch (A2AuthenticationException ex) {
            requestContext.abortWith(errorResponse(ex));
        } catch (A2SecurityException ex) {
            requestContext.abortWith(errorResponse(ex));
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        authenticator.clear();
    }

    private static Response errorResponse(A2SecurityException ex) {
        String json = "{\"error\":\"" + esc(ex.getErrorCode())
                + "\",\"message\":\"" + esc(ex.getMessage())
                + "\",\"status\":" + ex.httpStatus() + "}";
        return Response.status(ex.httpStatus()).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
