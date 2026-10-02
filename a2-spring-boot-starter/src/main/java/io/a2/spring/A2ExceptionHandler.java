package io.a2.spring;

import io.a2.core.exception.A2AuthenticationException;
import io.a2.core.exception.A2AuthorizationException;
import io.a2.core.exception.A2SecurityException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
@Order(0)
public class A2ExceptionHandler {

    @ExceptionHandler(A2AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthn(A2AuthenticationException ex) {
        return body(HttpStatus.UNAUTHORIZED, ex);
    }

    @ExceptionHandler(A2AuthorizationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthz(A2AuthorizationException ex) {
        return body(HttpStatus.FORBIDDEN, ex);
    }

    @ExceptionHandler(A2SecurityException.class)
    public ResponseEntity<Map<String, Object>> handleSecurity(A2SecurityException ex) {
        HttpStatus status = ex.httpStatus() == 401 ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN;
        return body(status, ex);
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<Map<String, Object>> handleLegacy(SecurityException ex) {
        String msg = ex.getMessage() != null ? ex.getMessage() : "Security error";
        boolean unauth = msg.toLowerCase().contains("authentication required")
                || msg.toLowerCase().contains("invalid")
                || msg.toLowerCase().contains("protocol not allowed");
        HttpStatus status = unauth ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN;
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("error", unauth ? "unauthorized" : "forbidden");
        map.put("message", msg);
        map.put("status", status.value());
        map.put("timestamp", Instant.now().toString());
        return ResponseEntity.status(status).body(map);
    }

    private static ResponseEntity<Map<String, Object>> body(HttpStatus status, A2SecurityException ex) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("error", ex.getErrorCode());
        map.put("message", ex.getMessage());
        map.put("status", status.value());
        map.put("timestamp", Instant.now().toString());
        return ResponseEntity.status(status).body(map);
    }
}
