package io.a2.quarkus;

import io.a2.core.exception.A2AuthenticationException;
import io.a2.core.exception.A2AuthorizationException;
import io.a2.core.exception.A2SecurityException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import java.time.Instant;

@Provider
public class A2ExceptionMapper implements ExceptionMapper<A2SecurityException> {

    @Override
    public Response toResponse(A2SecurityException ex) {
        int status = ex.httpStatus();
        String json = "{"
                + "\"error\":\"" + esc(ex.getErrorCode()) + "\","
                + "\"message\":\"" + esc(ex.getMessage()) + "\","
                + "\"status\":" + status + ","
                + "\"timestamp\":\"" + Instant.now() + "\""
                + "}";
        return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
    }

    @Provider
    public static class AuthnMapper implements ExceptionMapper<A2AuthenticationException> {
        private final A2ExceptionMapper delegate = new A2ExceptionMapper();
        @Override
        public Response toResponse(A2AuthenticationException exception) {
            return delegate.toResponse(exception);
        }
    }

    @Provider
    public static class AuthzMapper implements ExceptionMapper<A2AuthorizationException> {
        private final A2ExceptionMapper delegate = new A2ExceptionMapper();
        @Override
        public Response toResponse(A2AuthorizationException exception) {
            return delegate.toResponse(exception);
        }
    }

    @Provider
    public static class LegacySecurityMapper implements ExceptionMapper<SecurityException> {
        @Override
        public Response toResponse(SecurityException ex) {
            String msg = ex.getMessage() != null ? ex.getMessage() : "Security error";
            boolean unauth = msg.toLowerCase().contains("authentication")
                    || msg.toLowerCase().contains("protocol not allowed");
            int status = unauth ? 401 : 403;
            String json = "{"
                    + "\"error\":\"" + (unauth ? "unauthorized" : "forbidden") + "\","
                    + "\"message\":\"" + esc(msg) + "\","
                    + "\"status\":" + status
                    + "}";
            return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
