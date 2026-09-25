package io.a2.provider.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SAML 2.0 assertion validator.
 * Checks issuer, audience, NotBefore/NotOnOrAfter, optional signature.
 */
public class SamlAssertionValidator {

    private static final Logger log = LoggerFactory.getLogger(SamlAssertionValidator.class);

    private final String expectedAudience;
    private final String expectedIssuer;
    private final X509Certificate idpCertificate;
    private final long clockSkewSeconds;

    public SamlAssertionValidator(String expectedAudience, String expectedIssuer,
                                  X509Certificate idpCertificate, long clockSkewSeconds) {
        this.expectedAudience = expectedAudience;
        this.expectedIssuer = expectedIssuer;
        this.idpCertificate = idpCertificate;
        this.clockSkewSeconds = clockSkewSeconds > 0 ? clockSkewSeconds : 120;
    }

    public ValidationResult validate(String samlResponse) {
        try {
            String xml = decodeIfNeeded(samlResponse);
            String nameId = extract(xml, "NameID");
            String issuer = extract(xml, "Issuer");
            String notBefore = extractAttr(xml, "Conditions", "NotBefore");
            String notOnOrAfter = extractAttr(xml, "Conditions", "NotOnOrAfter");
            List<String> audiences = extractAll(xml, "Audience");
            String sessionIndex = extract(xml, "SessionIndex");
            Map<String, String> attributes = extractAttributes(xml);

            if (nameId == null || nameId.isBlank()) {
                return ValidationResult.failure("Missing NameID");
            }
            if (expectedIssuer != null && issuer != null && !expectedIssuer.equals(issuer)) {
                return ValidationResult.failure("Issuer mismatch: expected " + expectedIssuer + " got " + issuer);
            }
            if (expectedAudience != null && !audiences.isEmpty() && !audiences.contains(expectedAudience)) {
                return ValidationResult.failure("Audience restriction failed; expected " + expectedAudience);
            }

            Instant now = Instant.now();
            if (notBefore != null) {
                Instant nb = Instant.parse(notBefore);
                if (now.plusSeconds(clockSkewSeconds).isBefore(nb)) {
                    return ValidationResult.failure("Assertion not yet valid (NotBefore)");
                }
            }
            Instant notOnOrAfterInst = null;
            if (notOnOrAfter != null) {
                notOnOrAfterInst = Instant.parse(notOnOrAfter);
                if (now.minusSeconds(clockSkewSeconds).isAfter(notOnOrAfterInst)
                        || now.minusSeconds(clockSkewSeconds).equals(notOnOrAfterInst)) {
                    return ValidationResult.failure("Assertion expired (NotOnOrAfter)");
                }
            }

            boolean sigValid = false;
            if (idpCertificate != null) {
                sigValid = verifySignature(xml, idpCertificate.getPublicKey());
                if (!sigValid) {
                    return ValidationResult.failure("Signature validation failed");
                }
            }

            return ValidationResult.success(nameId, issuer, audiences, notOnOrAfterInst,
                    sessionIndex, attributes, sigValid);
        } catch (Exception e) {
            log.debug("SAML validation error: {}", e.getMessage());
            return ValidationResult.failure("SAML validation error: " + e.getMessage());
        }
    }

    private static String decodeIfNeeded(String input) {
        String t = input.trim();
        if (t.startsWith("<")) return t;
        try {
            return new String(Base64.getDecoder().decode(t.replaceAll("\\s", "")), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return t;
        }
    }

    private static String extract(String xml, String localName) {
        Pattern p = Pattern.compile(
                "<(?:[a-zA-Z0-9]+:)?" + localName + "[^>]*>([^<]*)</(?:[a-zA-Z0-9]+:)?" + localName + ">",
                Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(xml);
        return m.find() ? m.group(1).trim() : null;
    }

    private static String extractAttr(String xml, String element, String attr) {
        Pattern p = Pattern.compile(
                "<(?:[a-zA-Z0-9]+:)?" + element + "[^>]*\\b" + attr + "=\"([^\"]+)\"",
                Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(xml);
        return m.find() ? m.group(1).trim() : null;
    }

    private static List<String> extractAll(String xml, String localName) {
        List<String> out = new ArrayList<>();
        Pattern p = Pattern.compile(
                "<(?:[a-zA-Z0-9]+:)?" + localName + "[^>]*>([^<]*)</(?:[a-zA-Z0-9]+:)?" + localName + ">",
                Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(xml);
        while (m.find()) out.add(m.group(1).trim());
        return out;
    }

    private static Map<String, String> extractAttributes(String xml) {
        Map<String, String> attrs = new HashMap<>();
        Pattern p = Pattern.compile(
                "<(?:[a-zA-Z0-9]+:)?Attribute\\s+[^>]*Name=\"([^\"]+)\"[^>]*>\\s*"
                        + "<(?:[a-zA-Z0-9]+:)?AttributeValue[^>]*>([^<]*)</(?:[a-zA-Z0-9]+:)?AttributeValue>",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher m = p.matcher(xml);
        while (m.find()) {
            attrs.put(m.group(1).trim(), m.group(2).trim());
        }
        return attrs;
    }

    private boolean verifySignature(String xml, PublicKey publicKey) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

            Document doc = dbf.newDocumentBuilder()
                    .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                nl = doc.getElementsByTagName("Signature");
            }
            if (nl.getLength() == 0) {
                log.debug("No Signature element found");
                return false;
            }

            registerIdAttributes(doc.getDocumentElement());

            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));

            XMLSignature signature = factory.unmarshalXMLSignature(valContext);
            return signature.validate(valContext);
        } catch (Exception e) {
            log.debug("Signature verify failed: {}", e.getMessage());
            return false;
        }
    }

    private static void registerIdAttributes(Node node) {
        if (node == null) return;
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            Element el = (Element) node;
            if (el.hasAttribute("ID")) el.setIdAttribute("ID", true);
            if (el.hasAttribute("Id")) el.setIdAttribute("Id", true);
            if (el.hasAttribute("id")) el.setIdAttribute("id", true);
        }
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            registerIdAttributes(children.item(i));
        }
    }

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

    public static final class ValidationResult {
        private final boolean success;
        private final String error;
        private final String nameId;
        private final String issuer;
        private final List<String> audiences;
        private final Instant notOnOrAfter;
        private final String sessionIndex;
        private final Map<String, String> attributes;
        private final boolean signatureValid;

        private ValidationResult(boolean success, String error, String nameId, String issuer,
                                 List<String> audiences, Instant notOnOrAfter, String sessionIndex,
                                 Map<String, String> attributes, boolean signatureValid) {
            this.success = success;
            this.error = error;
            this.nameId = nameId;
            this.issuer = issuer;
            this.audiences = audiences != null ? audiences : List.of();
            this.notOnOrAfter = notOnOrAfter;
            this.sessionIndex = sessionIndex;
            this.attributes = attributes != null ? attributes : Map.of();
            this.signatureValid = signatureValid;
        }

        public static ValidationResult success(String nameId, String issuer, List<String> audiences,
                                               Instant notOnOrAfter, String sessionIndex,
                                               Map<String, String> attributes, boolean signatureValid) {
            return new ValidationResult(true, null, nameId, issuer, audiences, notOnOrAfter,
                    sessionIndex, attributes, signatureValid);
        }

        public static ValidationResult failure(String error) {
            return new ValidationResult(false, error, null, null, List.of(), null, null, Map.of(), false);
        }

        public boolean isSuccess() { return success; }
        public String getError() { return error; }
        public String getNameId() { return nameId; }
        public String getIssuer() { return issuer; }
        public List<String> getAudiences() { return audiences; }
        public Instant getNotOnOrAfter() { return notOnOrAfter; }
        public String getSessionIndex() { return sessionIndex; }
        public Map<String, String> getAttributes() { return attributes; }
        public boolean isSignatureValid() { return signatureValid; }

        public Set<String> rolesFromAttributes() {
            Set<String> roles = new HashSet<>();
            for (var e : attributes.entrySet()) {
                if (e.getKey().toLowerCase().contains("role")) {
                    for (String part : e.getValue().split(",")) {
                        if (!part.isBlank()) roles.add(part.trim());
                    }
                }
            }
            return roles;
        }
    }
}
