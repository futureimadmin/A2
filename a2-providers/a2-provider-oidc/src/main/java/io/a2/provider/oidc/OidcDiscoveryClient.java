package io.a2.provider.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenID Connect Discovery client.
 * Fetches and caches {@code /.well-known/openid-configuration}.
 *
 * Spec: https://openid.net/specs/openid-connect-discovery-1_0.html
 */
public class OidcDiscoveryClient {

    private static final Logger log = LoggerFactory.getLogger(OidcDiscoveryClient.class);
    private static final Duration DEFAULT_CACHE_TTL = Duration.ofHours(1);

    private final HttpClient http;
    private final Duration cacheTtl;
    private final Map<String, CachedDocument> cache = new ConcurrentHashMap<>();

    public OidcDiscoveryClient() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(), DEFAULT_CACHE_TTL);
    }

    public OidcDiscoveryClient(HttpClient http, Duration cacheTtl) {
        this.http = http;
        this.cacheTtl = cacheTtl != null ? cacheTtl : DEFAULT_CACHE_TTL;
    }

    /**
     * Resolve discovery document for the given issuer.
     * Appends {@code /.well-known/openid-configuration} if not already present.
     */
    public OidcDiscoveryDocument discover(String issuerOrDiscoveryUri) {
        String discoveryUri = normalizeDiscoveryUri(issuerOrDiscoveryUri);

        CachedDocument cached = cache.get(discoveryUri);
        if (cached != null && cached.expiresAt.isAfter(Instant.now())) {
            return cached.document;
        }

        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(discoveryUri))
                    .header("Accept", "application/json")
                    .GET()
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new OidcDiscoveryException(
                        "Discovery endpoint returned HTTP " + resp.statusCode() + " for " + discoveryUri);
            }

            OidcDiscoveryDocument doc = parse(resp.body(), discoveryUri);
            cache.put(discoveryUri, new CachedDocument(doc, Instant.now().plus(cacheTtl)));
            log.info("OIDC discovery loaded for issuer={} from {}", doc.getIssuer(), discoveryUri);
            return doc;
        } catch (OidcDiscoveryException e) {
            throw e;
        } catch (Exception e) {
            throw new OidcDiscoveryException("Failed to fetch OIDC discovery document from " + discoveryUri, e);
        }
    }

    /** Force refresh (ignore cache). */
    public OidcDiscoveryDocument refresh(String issuerOrDiscoveryUri) {
        String discoveryUri = normalizeDiscoveryUri(issuerOrDiscoveryUri);
        cache.remove(discoveryUri);
        return discover(issuerOrDiscoveryUri);
    }

    public void clearCache() {
        cache.clear();
    }

    static String normalizeDiscoveryUri(String issuerOrDiscoveryUri) {
        String u = issuerOrDiscoveryUri.trim();
        if (u.endsWith("/")) {
            u = u.substring(0, u.length() - 1);
        }
        if (u.contains("/.well-known/openid-configuration")) {
            return u;
        }
        return u + "/.well-known/openid-configuration";
    }

    /**
     * Minimal JSON parser sufficient for discovery documents.
     */
    @SuppressWarnings("unchecked")
    OidcDiscoveryDocument parse(String json, String sourceUri) {
        Map<String, Object> map = simpleJsonObject(json);

        String issuer = str(map, "issuer");
        if (issuer == null || issuer.isBlank()) {
            throw new OidcDiscoveryException("Discovery document missing required 'issuer' field (from " + sourceUri + ")");
        }

        return OidcDiscoveryDocument.builder()
                .issuer(issuer)
                .authorizationEndpoint(uri(map, "authorization_endpoint"))
                .tokenEndpoint(uri(map, "token_endpoint"))
                .userInfoEndpoint(uri(map, "userinfo_endpoint"))
                .jwksUri(uri(map, "jwks_uri"))
                .revocationEndpoint(uri(map, "revocation_endpoint"))
                .introspectionEndpoint(uri(map, "introspection_endpoint"))
                .endSessionEndpoint(uri(map, "end_session_endpoint"))
                .scopesSupported(strList(map, "scopes_supported"))
                .responseTypesSupported(strList(map, "response_types_supported"))
                .subjectTypesSupported(strList(map, "subject_types_supported"))
                .idTokenSigningAlgValuesSupported(strList(map, "id_token_signing_alg_values_supported"))
                .tokenEndpointAuthMethodsSupported(strList(map, "token_endpoint_auth_methods_supported"))
                .claimsSupported(strList(map, "claims_supported"))
                .raw(map)
                .build();
    }

    private static Map<String, Object> simpleJsonObject(String json) {
        Map<String, Object> result = new HashMap<>();
        String s = json.trim();
        if (!s.startsWith("{") || !s.endsWith("}")) {
            throw new OidcDiscoveryException("Invalid JSON object");
        }
        int i = 1;
        int n = s.length() - 1;
        while (i < n) {
            while (i < n && Character.isWhitespace(s.charAt(i))) i++;
            if (i >= n || s.charAt(i) == '}') break;
            if (s.charAt(i) != '"') {
                i++;
                continue;
            }
            int keyStart = ++i;
            while (i < n && s.charAt(i) != '"') i++;
            String key = s.substring(keyStart, i);
            i++;
            while (i < n && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ':')) i++;
            if (i >= n) break;

            Object value;
            char c = s.charAt(i);
            if (c == '"') {
                int vs = ++i;
                while (i < n && s.charAt(i) != '"') {
                    if (s.charAt(i) == '\\') i++;
                    i++;
                }
                value = s.substring(vs, i);
                i++;
            } else if (c == '[') {
                List<String> list = new ArrayList<>();
                i++;
                while (i < n && s.charAt(i) != ']') {
                    while (i < n && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ',')) i++;
                    if (i < n && s.charAt(i) == '"') {
                        int vs = ++i;
                        while (i < n && s.charAt(i) != '"') {
                            if (s.charAt(i) == '\\') i++;
                            i++;
                        }
                        list.add(s.substring(vs, i));
                        i++;
                    } else {
                        break;
                    }
                }
                if (i < n && s.charAt(i) == ']') i++;
                value = list;
            } else if (c == 't' || c == 'f' || c == 'n' || Character.isDigit(c) || c == '-') {
                int vs = i;
                while (i < n && s.charAt(i) != ',' && s.charAt(i) != '}') i++;
                value = s.substring(vs, i).trim();
            } else {
                i++;
                continue;
            }
            result.put(key, value);
            while (i < n && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ',')) i++;
        }
        return result;
    }

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private static URI uri(Map<String, Object> m, String key) {
        String s = str(m, key);
        if (s == null || s.isBlank()) return null;
        try {
            return URI.create(s);
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> strList(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object o : list) out.add(String.valueOf(o));
            return out;
        }
        return Collections.emptyList();
    }

    private static final class CachedDocument {
        final OidcDiscoveryDocument document;
        final Instant expiresAt;

        CachedDocument(OidcDiscoveryDocument document, Instant expiresAt) {
            this.document = document;
            this.expiresAt = expiresAt;
        }
    }

    public static class OidcDiscoveryException extends RuntimeException {
        public OidcDiscoveryException(String msg) { super(msg); }
        public OidcDiscoveryException(String msg, Throwable cause) { super(msg, cause); }
    }
}
