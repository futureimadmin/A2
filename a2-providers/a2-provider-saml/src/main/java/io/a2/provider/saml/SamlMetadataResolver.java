package io.a2.provider.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SAML 2.0 Metadata resolver (IdP / SP).
 *
 * Parses EntityDescriptor for:
 * - entityID
 * - SingleSignOnService / SingleLogoutService locations
 * - X509Certificate (signing / encryption)
 *
 * When OpenSAML 5.x is on the classpath, prefer {@link OpenSamlSupport}
 * for full schema validation and encrypted assertion handling.
 */
public class SamlMetadataResolver {

    private static final Logger log = LoggerFactory.getLogger(SamlMetadataResolver.class);

    private static final Pattern ENTITY_ID =
            Pattern.compile("entityID=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern SSO_LOCATION =
            Pattern.compile(
                    "<(?:[a-zA-Z0-9]+:)?SingleSignOnService[^>]*Location=\"([^\"]+)\"",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern SLO_LOCATION =
            Pattern.compile(
                    "<(?:[a-zA-Z0-9]+:)?SingleLogoutService[^>]*Location=\"([^\"]+)\"",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern X509_CERT =
            Pattern.compile(
                    "<(?:[a-zA-Z0-9]+:)?X509Certificate>([A-Za-z0-9+/=\\s]+)</(?:[a-zA-Z0-9]+:)?X509Certificate>",
                    Pattern.CASE_INSENSITIVE);

    private final HttpClient http;
    private final ConcurrentHashMap<String, CachedMetadata> cache = new ConcurrentHashMap<>();
    private final Duration cacheTtl;

    public SamlMetadataResolver() {
        this(Duration.ofHours(1));
    }

    public SamlMetadataResolver(Duration cacheTtl) {
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
        this.cacheTtl = cacheTtl;
    }

    public IdpMetadata resolveFromUrl(String metadataUrl) {
        CachedMetadata cached = cache.get(metadataUrl);
        if (cached != null && cached.expiresAt.isAfter(Instant.now())) {
            return cached.metadata;
        }
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(metadataUrl))
                    .header("Accept", "application/samlmetadata+xml, application/xml, text/xml")
                    .GET()
                    .timeout(Duration.ofSeconds(30))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new SamlMetadataException("Metadata HTTP " + resp.statusCode() + " from " + metadataUrl);
            }
            IdpMetadata md = parse(resp.body());
            cache.put(metadataUrl, new CachedMetadata(md, Instant.now().plus(cacheTtl)));
            return md;
        } catch (SamlMetadataException e) {
            throw e;
        } catch (Exception e) {
            throw new SamlMetadataException("Failed to fetch metadata from " + metadataUrl, e);
        }
    }

    public IdpMetadata resolveFromXml(String xml) {
        return parse(xml);
    }

    public IdpMetadata resolveFromStream(InputStream in) throws Exception {
        return parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
    }

    IdpMetadata parse(String xml) {
        String entityId = extract(ENTITY_ID, xml);
        if (entityId == null) {
            throw new SamlMetadataException("No entityID in metadata");
        }
        List<String> sso = extractAll(SSO_LOCATION, xml);
        List<String> slo = extractAll(SLO_LOCATION, xml);
        List<X509Certificate> certs = new ArrayList<>();
        Matcher m = X509_CERT.matcher(xml);
        while (m.find()) {
            try {
                String pem = m.group(1).replaceAll("\\s", "");
                byte[] der = Base64.getDecoder().decode(pem);
                certs.add(SamlAssertionValidator.loadCertificate(der));
            } catch (Exception e) {
                log.debug("Skipping unparseable certificate in metadata: {}", e.getMessage());
            }
        }
        return new IdpMetadata(entityId,
                sso.isEmpty() ? null : sso.get(0),
                slo.isEmpty() ? null : slo.get(0),
                sso, slo, certs);
    }

    private static String extract(Pattern p, String xml) {
        Matcher m = p.matcher(xml);
        return m.find() ? m.group(1).trim() : null;
    }

    private static List<String> extractAll(Pattern p, String xml) {
        List<String> list = new ArrayList<>();
        Matcher m = p.matcher(xml);
        while (m.find()) list.add(m.group(1).trim());
        return list;
    }

    public record IdpMetadata(
            String entityId,
            String ssoUrl,
            String sloUrl,
            List<String> ssoUrls,
            List<String> sloUrls,
            List<X509Certificate> certificates
    ) {
        public Optional<X509Certificate> primarySigningCert() {
            return certificates.isEmpty() ? Optional.empty() : Optional.of(certificates.get(0));
        }
    }

    private static final class CachedMetadata {
        final IdpMetadata metadata;
        final Instant expiresAt;
        CachedMetadata(IdpMetadata metadata, Instant expiresAt) {
            this.metadata = metadata;
            this.expiresAt = expiresAt;
        }
    }

    public static class SamlMetadataException extends RuntimeException {
        public SamlMetadataException(String msg) { super(msg); }
        public SamlMetadataException(String msg, Throwable c) { super(msg, c); }
    }
}
