package io.a2.core.auth;

import io.a2.annotations.Protocol;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Extracts credentials and candidate protocol(s) from HTTP-style headers.
 * Used by Spring / Quarkus auth filters before invoking ProtocolProviders.
 */
public final class CredentialExtractor {

    public static final String HDR_AUTHORIZATION = "Authorization";
    public static final String HDR_API_KEY = "X-API-Key";
    public static final String HDR_API_KEY_ALT = "X-Api-Key";
    public static final String HDR_SSO_PROVIDER = "X-A2-SSO-Provider";
    public static final String HDR_MERCHANT_ID = "X-Merchant-Id";

    private CredentialExtractor() {}

    public record Extracted(
            String credentials,
            Protocol preferred,
            String ssoName,
            Map<String, String> headers
    ) {
        public boolean isEmpty() {
            return credentials == null || credentials.isBlank();
        }
    }

    public static Extracted extract(HeaderLookup headerLookup) {
        Map<String, String> normalized = new LinkedHashMap<>();
        putIfPresent(normalized, headerLookup, HDR_AUTHORIZATION);
        putIfPresent(normalized, headerLookup, HDR_API_KEY);
        putIfPresent(normalized, headerLookup, HDR_API_KEY_ALT);
        putIfPresent(normalized, headerLookup, HDR_SSO_PROVIDER);
        putIfPresent(normalized, headerLookup, HDR_MERCHANT_ID);
        putIfPresent(normalized, headerLookup, "Content-Type");

        String auth = first(headerLookup, HDR_AUTHORIZATION);
        String apiKey = first(headerLookup, HDR_API_KEY);
        if (apiKey == null || apiKey.isBlank()) {
            apiKey = first(headerLookup, HDR_API_KEY_ALT);
        }
        String ssoName = first(headerLookup, HDR_SSO_PROVIDER);
        if (ssoName != null) {
            ssoName = ssoName.trim().toLowerCase(Locale.ROOT);
        }

        if (apiKey != null && !apiKey.isBlank()) {
            return new Extracted(apiKey.trim(), Protocol.API_KEY, ssoName, normalized);
        }

        if (auth != null && !auth.isBlank()) {
            String a = auth.trim();
            String lower = a.toLowerCase(Locale.ROOT);
            if (lower.startsWith("bearer ")) {
                String token = a.substring(7).trim();
                Protocol preferred = guessBearerProtocol(token, ssoName);
                return new Extracted(token, preferred, ssoName, normalized);
            }
            if (lower.startsWith("apikey ") || lower.startsWith("api-key ")) {
                int sp = a.indexOf(' ');
                return new Extracted(a.substring(sp + 1).trim(), Protocol.API_KEY, ssoName, normalized);
            }
            if (lower.startsWith("basic ")) {
                return new Extracted(a.substring(6).trim(), Protocol.BASIC, ssoName, normalized);
            }
            if (lower.startsWith("negotiate ") || lower.startsWith("kerberos ")) {
                int sp = a.indexOf(' ');
                return new Extracted(a.substring(sp + 1).trim(), Protocol.KERBEROS, ssoName, normalized);
            }
            return new Extracted(a, Protocol.JWT, ssoName, normalized);
        }

        return new Extracted(null, null, ssoName, normalized);
    }

    private static Protocol guessBearerProtocol(String token, String ssoName) {
        if (ssoName != null && !ssoName.isBlank()) {
            return Protocol.SSO;
        }
        long dots = token.chars().filter(c -> c == '.').count();
        if (dots >= 2) {
            return Protocol.JWT;
        }
        return Protocol.OIDC;
    }

    private static void putIfPresent(Map<String, String> map, HeaderLookup lookup, String name) {
        String v = lookup.get(name);
        if (v != null && !v.isBlank()) {
            map.put(name.toLowerCase(Locale.ROOT), v);
        }
    }

    private static String first(HeaderLookup lookup, String name) {
        return lookup.get(name);
    }

    @FunctionalInterface
    public interface HeaderLookup {
        String get(String name);
    }
}
