package io.a2.provider.saml;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SamlMetadataResolverTest {

    @Test
    void parseEntityDescriptor() {
        String xml = """
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                entityID="https://idp.example.com">
              <md:IDPSSODescriptor>
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data>
                      <ds:X509Certificate>MIIBkTCB+wIJAKHBfHEXAMPLE</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://idp.example.com/sso"/>
                <md:SingleLogoutService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://idp.example.com/slo"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>
            """;

        SamlMetadataResolver resolver = new SamlMetadataResolver();
        SamlMetadataResolver.IdpMetadata md = resolver.resolveFromXml(xml);

        assertEquals("https://idp.example.com", md.entityId());
        assertEquals("https://idp.example.com/sso", md.ssoUrl());
        assertEquals("https://idp.example.com/slo", md.sloUrl());
    }

    @Test
    void missingEntityIdFails() {
        SamlMetadataResolver resolver = new SamlMetadataResolver();
        assertThrows(SamlMetadataResolver.SamlMetadataException.class,
                () -> resolver.resolveFromXml("<md:EntityDescriptor></md:EntityDescriptor>"));
    }

    @Test
    void openSamlAvailabilityCheckDoesNotThrow() {
        // Just ensure the static check runs
        boolean available = OpenSamlSupport.isOpenSamlAvailable();
        assertNotNull(Boolean.valueOf(available));
    }

    @Test
    void detectEncryptedAssertion() {
        assertTrue(OpenSamlSupport.containsEncryptedAssertion(
                "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>"));
        assertFalse(OpenSamlSupport.containsEncryptedAssertion(
                "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>"));
    }
}
