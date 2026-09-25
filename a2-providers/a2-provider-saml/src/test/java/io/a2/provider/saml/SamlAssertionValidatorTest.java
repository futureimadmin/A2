package io.a2.provider.saml;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SamlAssertionValidatorTest {

    private static final String SP = "https://sp.example.com";
    private static final String IDP = "https://idp.example.com";

    @Test
    void validatesValidAssertion() {
        Instant now = Instant.now();
        String xml = assertionXml("alice@example.com", IDP, SP,
                now.minusSeconds(60).toString(),
                now.plusSeconds(3600).toString(),
                "admin");
        String b64 = Base64.getEncoder().encodeToString(xml.getBytes());

        SamlAssertionValidator validator = new SamlAssertionValidator(SP, IDP, null, 120);
        var result = validator.validate(b64);

        assertTrue(result.isSuccess(), result.getError());
        assertEquals("alice@example.com", result.getNameId());
        assertEquals(IDP, result.getIssuer());
        assertTrue(result.getAudiences().contains(SP));
    }

    @Test
    void rejectsWrongAudience() {
        Instant now = Instant.now();
        String xml = assertionXml("bob", IDP, "https://other-sp.com",
                now.minusSeconds(60).toString(),
                now.plusSeconds(3600).toString(), null);
        SamlAssertionValidator validator = new SamlAssertionValidator(SP, IDP, null, 120);
        var result = validator.validate(xml);
        assertFalse(result.isSuccess());
        assertTrue(result.getError().toLowerCase().contains("audience"));
    }

    @Test
    void rejectsExpiredAssertion() {
        Instant now = Instant.now();
        String xml = assertionXml("carol", IDP, SP,
                now.minusSeconds(7200).toString(),
                now.minusSeconds(3600).toString(), null);
        SamlAssertionValidator validator = new SamlAssertionValidator(SP, IDP, null, 120);
        var result = validator.validate(xml);
        assertFalse(result.isSuccess());
        assertTrue(result.getError().toLowerCase().contains("expired")
                || result.getError().toLowerCase().contains("notonorafter"));
    }

    @Test
    void rejectsWrongIssuer() {
        Instant now = Instant.now();
        String xml = assertionXml("dave", "https://evil-idp.com", SP,
                now.minusSeconds(60).toString(),
                now.plusSeconds(3600).toString(), null);
        SamlAssertionValidator validator = new SamlAssertionValidator(SP, IDP, null, 120);
        var result = validator.validate(xml);
        assertFalse(result.isSuccess());
        assertTrue(result.getError().toLowerCase().contains("issuer"));
    }

    @Test
    void extractsRolesFromAttributes() {
        Instant now = Instant.now();
        String xml = assertionXml("erin", IDP, SP,
                now.minusSeconds(60).toString(),
                now.plusSeconds(3600).toString(),
                "admin,user");
        SamlAssertionValidator validator = new SamlAssertionValidator(SP, null, null, 120);
        var result = validator.validate(xml);
        assertTrue(result.isSuccess());
        assertTrue(result.rolesFromAttributes().contains("admin"));
    }

    @Test
    void logoutRequestContainsNameId() {
        SamlSingleLogout slo = new SamlSingleLogout(SP, "https://idp.example.com/slo");
        String req = slo.buildLogoutRequest("alice@example.com", "session-1");
        assertTrue(req.contains("LogoutRequest"));
        assertTrue(req.contains("alice@example.com"));
        assertTrue(req.contains("session-1"));
    }

    private static String assertionXml(String nameId, String issuer, String audience,
                                       String notBefore, String notOnOrAfter, String roles) {
        StringBuilder sb = new StringBuilder();
        sb.append("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
        sb.append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">");
        sb.append("<saml:Assertion>");
        sb.append("<saml:Issuer>").append(issuer).append("</saml:Issuer>");
        sb.append("<saml:Subject><saml:NameID>").append(nameId).append("</saml:NameID></saml:Subject>");
        sb.append("<saml:Conditions NotBefore=\"").append(notBefore);
        sb.append("\" NotOnOrAfter=\"").append(notOnOrAfter).append("\">");
        sb.append("<saml:AudienceRestriction><saml:Audience>").append(audience);
        sb.append("</saml:Audience></saml:AudienceRestriction>");
        sb.append("</saml:Conditions>");
        if (roles != null) {
            sb.append("<saml:AttributeStatement>");
            sb.append("<saml:Attribute Name=\"Role\"><saml:AttributeValue>");
            sb.append(roles).append("</saml:AttributeValue></saml:Attribute>");
            sb.append("</saml:AttributeStatement>");
        }
        sb.append("</saml:Assertion></samlp:Response>");
        return sb.toString();
    }
}
