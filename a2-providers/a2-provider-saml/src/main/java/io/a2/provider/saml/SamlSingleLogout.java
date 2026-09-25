package io.a2.provider.saml;

import java.time.Instant;
import java.util.UUID;

/**
 * SAML 2.0 Single Logout (SLO) request/response builder.
 *
 * Produces LogoutRequest / LogoutResponse XML for HTTP-Redirect or HTTP-POST binding.
 * Signature is left to the caller (or OpenSAML) when required by the IdP.
 */
public class SamlSingleLogout {

    private final String spEntityId;
    private final String idpSloUrl;

    public SamlSingleLogout(String spEntityId, String idpSloUrl) {
        this.spEntityId = spEntityId;
        this.idpSloUrl = idpSloUrl;
    }

    /**
     * Build a LogoutRequest for the given NameID and optional SessionIndex.
     */
    public String buildLogoutRequest(String nameId, String sessionIndex) {
        String id = "_" + UUID.randomUUID();
        String issueInstant = Instant.now().toString();
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.append("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
        sb.append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
        sb.append("ID=\"").append(id).append("\" Version=\"2.0\" ");
        sb.append("IssueInstant=\"").append(issueInstant).append("\" ");
        sb.append("Destination=\"").append(idpSloUrl).append("\">");
        sb.append("<saml:Issuer>").append(spEntityId).append("</saml:Issuer>");
        sb.append("<saml:NameID>").append(escape(nameId)).append("</saml:NameID>");
        if (sessionIndex != null && !sessionIndex.isBlank()) {
            sb.append("<samlp:SessionIndex>").append(escape(sessionIndex)).append("</samlp:SessionIndex>");
        }
        sb.append("</samlp:LogoutRequest>");
        return sb.toString();
    }

    /**
     * Build a LogoutResponse acknowledging a LogoutRequest.
     */
    public String buildLogoutResponse(String inResponseTo, boolean success) {
        String id = "_" + UUID.randomUUID();
        String issueInstant = Instant.now().toString();
        String status = success
                ? "urn:oasis:names:tc:SAML:2.0:status:Success"
                : "urn:oasis:names:tc:SAML:2.0:status:Responder";
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.append("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
        sb.append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
        sb.append("ID=\"").append(id).append("\" Version=\"2.0\" ");
        sb.append("IssueInstant=\"").append(issueInstant).append("\" ");
        if (inResponseTo != null) {
            sb.append("InResponseTo=\"").append(inResponseTo).append("\" ");
        }
        sb.append("Destination=\"").append(idpSloUrl).append("\">");
        sb.append("<saml:Issuer>").append(spEntityId).append("</saml:Issuer>");
        sb.append("<samlp:Status><samlp:StatusCode Value=\"").append(status).append("\"/></samlp:Status>");
        sb.append("</samlp:LogoutResponse>");
        return sb.toString();
    }

    public String getIdpSloUrl() {
        return idpSloUrl;
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
