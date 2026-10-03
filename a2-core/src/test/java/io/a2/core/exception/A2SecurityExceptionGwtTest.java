package io.a2.core.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("A2 security exceptions — GivenWhenThen")
class A2SecurityExceptionGwtTest {

    @Nested
    @DisplayName("Given A2AuthenticationException factories")
    class AuthN {

        @Test
        @DisplayName("When required(), Then code authentication_required and status 401")
        void givenRequired_whenCreated_then401() {
            A2AuthenticationException ex = A2AuthenticationException.required();
            assertEquals(401, ex.httpStatus());
            assertEquals("authentication_required", ex.getErrorCode());
        }

        @Test
        @DisplayName("When invalid(detail), Then code invalid_credentials")
        void givenInvalid_whenCreated_thenInvalidCredentials() {
            A2AuthenticationException ex = A2AuthenticationException.invalid("expired jwt");
            assertEquals(401, ex.httpStatus());
            assertEquals("invalid_credentials", ex.getErrorCode());
            assertTrue(ex.getMessage().contains("expired") || ex.getMessage().toLowerCase().contains("invalid"));
        }

        @Test
        @DisplayName("When protocolNotAllowed, Then message includes protocol")
        void givenProtocol_whenNotAllowed_thenMessageHasProtocol() {
            A2AuthenticationException ex = A2AuthenticationException.protocolNotAllowed("SAML");
            assertTrue(ex.getMessage().contains("SAML"));
        }
    }

    @Nested
    @DisplayName("Given A2AuthorizationException")
    class AuthZ {

        @Test
        @DisplayName("When denied, Then status 403")
        void givenDenied_whenCreated_then403() {
            A2AuthorizationException ex = A2AuthorizationException.deniedByProvider();
            assertEquals(403, ex.httpStatus());
        }

        @Test
        @DisplayName("When message constructor, Then status 403")
        void givenMessage_whenCreated_then403() {
            A2AuthorizationException ex = new A2AuthorizationException("no access");
            assertEquals(403, ex.httpStatus());
        }
    }
}
