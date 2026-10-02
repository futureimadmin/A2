package io.a2.spring;

import io.a2.core.auth.RequestAuthenticator;
import io.a2.core.exception.A2AuthenticationException;
import io.a2.core.exception.A2SecurityException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;

@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class A2AuthenticationFilter extends OncePerRequestFilter {

    private final RequestAuthenticator authenticator;
    private final boolean failOnInvalidCredentials;

    public A2AuthenticationFilter(RequestAuthenticator authenticator) {
        this(authenticator, true);
    }

    public A2AuthenticationFilter(RequestAuthenticator authenticator, boolean failOnInvalidCredentials) {
        this.authenticator = authenticator;
        this.failOnInvalidCredentials = failOnInvalidCredentials;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            authenticator.authenticate(name -> header(request, name), false);
            filterChain.doFilter(request, response);
        } catch (A2AuthenticationException ex) {
            if (!failOnInvalidCredentials) {
                authenticator.clear();
                filterChain.doFilter(request, response);
                return;
            }
            writeError(response, ex);
        } catch (A2SecurityException ex) {
            writeError(response, ex);
        } finally {
            authenticator.clear();
        }
    }

    private static String header(HttpServletRequest request, String name) {
        String v = request.getHeader(name);
        if (v != null) return v;
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) return null;
        String target = name.toLowerCase(Locale.ROOT);
        for (String n : Collections.list(names)) {
            if (n != null && n.toLowerCase(Locale.ROOT).equals(target)) {
                return request.getHeader(n);
            }
        }
        return null;
    }

    private static void writeError(HttpServletResponse response, A2SecurityException ex) throws IOException {
        if (response.isCommitted()) return;
        response.setStatus(ex.httpStatus());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        String body = "{\"error\":\"" + escape(ex.getErrorCode())
                + "\",\"message\":\"" + escape(ex.getMessage())
                + "\",\"status\":" + ex.httpStatus() + "}";
        response.getWriter().write(body);
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ");
    }
}
