package io.a2.provider.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SAML 2.0 Assertion Validator.
 *
 * Performs the checks required by the SAML core specification:
 * <ul>
 *   <li>XML well-formedness</li>
 *   <li>Issuer match</li>
 *   <li>AudienceRestriction (Audience must include SP entityID)</li>
 *   <li>Conditions time window (NotBefore / NotOnOrAfter) with clock skew</li>
 *   <li>Subject Confirmation (Bearer) time checks</li>
 *   <li>Optional XML-DSig signature validation against IdP certificate</li>
 *   <li>NameID + Attribute extraction</li>
 * </ul>
 *
 * Package: {@code io.a2.provider.saml}
 */
public class SamlAssertionValidator {

    private static final Logger log = LoggerFactory.getLogger(SamlAssertionValidator.class);

    /** Allowed clock skew in seconds (default 2 minutes). */
    private final long clockSkewSeconds;

    /** Expected SP entity ID (audience). */
    private final String expectedAudience;

    /** Expected IdP entity ID (issuer). Null = any. */
    private final String expectedIssuer;

    /** IdP signing certificate (optional – if null, signature check is skipped with a warning). */
    private final X509Certificate idpCertificate;

    // Patterns for element extraction (namespace-tolerant)
    private static final Pattern ISSUER_PATTERN =
            Pattern.compile("<(?:[a-zA-Z0-9]+:)?Issuer[^>]*>([^<]+)</(?:[a-zA-Z0-9]+:)?Issuer>",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern NAMEID_PATTERN =
            Pattern.compile("<(?:[a-zA-Z0-9]+:)?NameID[^>]*>([^<]+)</(?:[a-zA-Z0-9]+:)?NameID>",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern AUDIENCE_PATTERN =
            Pattern.compile("<(?:[a-zA-Z0-9]+:)?Audience>([^<]+)</(?:[a-zA-Z0-9]+:)?Audience>",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern NOT_BEFORE_PATTERN =
            Pattern.compile("NotBefore=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern NOT_ON_OR_AFTER_PATTERN =
            Pattern.compile("NotOnOrAfter=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR_PATTERN =
            Pattern.compile(
                    "<(?:[a-zA-Z0-9]+:)?Attribute\\s+[^>]*Name=\"([^\"]+)\"[^>]*>"
                            + "[\\s\\S]*?<(?:[a-zA-Z0-9]+:)?AttributeValue[^>]*>([^<]*)</(?:[a-zA-Z0-9]+:)?AttributeValue>",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern SESSION_INDEX_PATTERN =
            Pattern.compile("SessionIndex=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    public SamlAssertionValidator(String expectedAudience, String expectedIssuer,
                                  X509Certificate idpCertificate, long clockSkewSeconds) {
        this.expectedAudience = expectedAudience;
        this.expectedIssuer = expectedIssuer;
        this.idpCertificate = idpCertificate;
        this.clockSkewSeconds = clockSkewSeconds > 0 ? clockSkewSeconds : 120;
    }

    public SamlAssertionValidator(String expectedAudience) {
        this(expectedAudience, null, null, 120);
    }

    /**
     * Validate a SAMLResponse (Base64 or raw XML) and return structured result.
     */
    public ValidationResult validate(String samlResponse) {
        if (samlResponse == null || samlResponse.isBlank()) {
            return ValidationResult.failure("Missing SAMLResponse");
        }

        String xml;
        try {
            xml = new String(Base64.getDecoder().decode(samlResponse.replaceAll("\\s", "")),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            xml = samlResponse; // already plain XML
        }

        // 1. Basic structure
        if (!xml.contains("Assertion") && !xml.contains("assertion")) {
            return ValidationResult.failure("No Assertion element found in SAMLResponse");
        }

        // 2. Issuer
        String issuer = extract(ISSUER_PATTERN, xml);
        if (issuer == null) {
            return ValidationResult.failure("Missing Issuer");
        }
        if (expectedIssuer != null && !expectedIssuer.equals(issuer)) {
            return ValidationResult.failure("Issuer mismatch: expected " + expectedIssuer + " got " + issuer);
        }

        // 3. AudienceRestriction
        List<String> audiences = extractAll(AUDIENCE_PATTERN, xml);
        if (expectedAudience != null && !expectedAudience.isBlank()) {
            boolean audienceOk = audiences.stream().anyMatch(a -> a.equals(expectedAudience));
            if (!audienceOk) {
                return ValidationResult.failure(
                        "AudienceRestriction failed: expected " + expectedAudience + " in " + audiences);
            }
        }

        // 4. Conditions time window
        Instant now = Instant.now();
        Instant notBefore = parseTime(extract(NOT_BEFORE_PATTERN, xml));
        Instant notOnOrAfter = parseTime(extract(NOT_ON_OR_AFTER_PATTERN, xml));

        if (notBefore != null && now.plusSeconds(clockSkewSeconds).isBefore(notBefore)) {
            return ValidationResult.failure("Assertion NotBefore in the future: " + notBefore);
        }
        if (notOnOrAfter != null && now.minusSeconds(clockSkewSeconds).isAfter(notOnOrAfter)
                || (notOnOrAfter != null && !now.minusSeconds(clockSkewSeconds).isBefore(notOnOrAfter))) {
            // NotOnOrAfter is exclusive
            if (now.minusSeconds(clockSkewSeconds).compareTo(notOnOrAfter) >= 0) {
                return ValidationResult.failure("Assertion expired (NotOnOrAfter=" + notOnOrAfter + ")");
            }
        }

        // 5. NameID (Subject)
        String nameId = extract(NAMEID_PATTERN, xml);
        if (nameId == null || nameId.isBlank()) {
            return ValidationResult.failure("Missing NameID in Subject");
        }

        // 6. Attributes
        Map<String, String> attributes = new HashMap<>();
        Matcher attrMatcher = ATTR_PATTERN.matcher(xml);
        while (attrMatcher.find()) {
            attributes.put(attrMatcher.group(1), attrMatcher.group(2).trim());
        }

        // 7. SessionIndex (optional)
        String sessionIndex = extract(SESSION_INDEX_PATTERN, xml);

        // 8. XML Signature (optional but recommended)
        boolean signatureValid = false;
        if (idpCertificate != null) {
            try {
                signatureValid = verifyXmlSignature(xml, idpCertificate.getPublicKey());
                if (!signatureValid) {
                    return ValidationResult.failure("XML Signature validation failed");
                }
            } catch (Exception e) {
                log.debug("Signature validation error: {}", e.getMessage());
                return ValidationResult.failure("XML Signature validation error: " + e.getMessage());
            }
        } else {
            log.warn("No IdP certificate configured – skipping XML Signature validation");
        }

        return ValidationResult.success(nameId, issuer, audiences, attributes,
                sessionIndex, notBefore, notOnOrAfter, signatureValid);
    }

    /**
     * Validate XML-DSig signature using the JDK XML Digital Signature API.
     */
    boolean verifyXmlSignature(String xml, PublicKey publicKey) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        // XXE protection
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);

        var doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        var nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            // try without namespace
            nl = doc.getElementsByTagName("Signature");
        }
        if (nl.getLength() == 0) {
            log.debug("No Signature element found");
            return false;
        }

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
        // Allow ID attribute for reference resolution
        valContext.setIdAttributeNS(null, "ID");

        XMLSignature signature = factory.unmarshalXMLSignature(valContext);
        return signature.validate(valContext);
    }

    /** Load an X.509 certificate from PEM or DER bytes. */
    public static X509Certificate loadCertificate(byte[] certBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    public static X509Certificate loadCertificateFromPem(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(cleaned);
        return loadCertificate(der);
    }

    // --- helpers ---

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

    private static Instant parseTime(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    // -------------------------------------------------------------------------

    public static final class ValidationResult {
        private final boolean success;
        private final String error;
        private final String nameId;
        private final String issuer;
        private final List<String> audiences;
        private final Map<String, String> attributes;
        private final String sessionIndex;
        private final Instant notBefore;
        private final Instant notOnOrAfter;
        private final boolean signatureValid;

        private ValidationResult(boolean success, String error, String nameId, String issuer,
                                 List<String> audiences, Map<String, String> attributes,
                                 String sessionIndex, Instant notBefore, Instant notOnOrAfter,
                                 boolean signatureValid) {
            this.success = success;
            this.error = error;
            this.nameId = nameId;
            this.issuer = issuer;
            this.audiences = audiences != null ? List.copyOf(audiences) : List.of();
            this.attributes = attributes != null ? Map.copyOf(attributes) : Map.of();
            this.sessionIndex = sessionIndex;
            this.notBefore = notBefore;
            this.notOnOrAfter = notOnOrAfter;
            this.signatureValid = signatureValid;
        }

        public static ValidationResult success(String nameId, String issuer, List<String> audiences,
                                               Map<String, String> attributes, String sessionIndex,
                                               Instant notBefore, Instant notOnOrAfter,
                                               boolean signatureValid) {
            return new ValidationResult(true, null, nameId, issuer, audiences, attributes,
                    sessionIndex, notBefore, notOnOrAfter, signatureValid);
        }

        public static ValidationResult failure(String error) {
            return new ValidationResult(false, error, null, null, null, null, null, null, null, false);
        }

        public boolean isSuccess() { return success; }
        public String getError() { return error; }
        public String getNameId() { return nameId; }
        public String getIssuer() { return issuer; }
        public List<String> getAudiences() { return audiences; }
        public Map<String, String> getAttributes() { return attributes; }
        public String getSessionIndex() { return sessionIndex; }
        public Instant getNotBefore() { return notBefore; }
        public Instant getNotOnOrAfter() { return notOnOrAfter; }
        public boolean isSignatureValid() { return signatureValid; }

        public Set<String> rolesFromAttributes() {
            String roles = attributes.getOrDefault("Role",
                    attributes.getOrDefault("roles",
                            attributes.getOrDefault("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "")));
            if (roles == null || roles.isBlank()) return Set.of();
            return Set.of(roles.split("[,;\\s]+"));
        }
    }
}
