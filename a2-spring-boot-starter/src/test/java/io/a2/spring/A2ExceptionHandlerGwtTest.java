package io.a2.spring;

import io.a2.core.exception.A2AuthenticationException;
import io.a2.core.exception.A2AuthorizationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("A2 exception HTTP mapping — GivenWhenThen")
class A2ExceptionHandlerGwtTest {

    @Nested
    @DisplayName("Given A2AuthenticationException")
    class AuthN {

        @Test
        @DisplayName("When required(), Then httpStatus 401")
        void givenRequired_whenHttpStatus_then401() {
            assertEquals(401, A2AuthenticationException.required().httpStatus());
        }

        @Test
        @DisplayName("When invalid(detail), Then message contains detail")
        void givenInvalid_whenMessage_thenContainsDetail() {
            var ex = A2AuthenticationException.invalid("expired");
            assertEquals(401, ex.httpStatus());
            assertTrue(ex.getMessage().toLowerCase().contains("expired")
                    || ex.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Nested
    @DisplayName("Given A2AuthorizationException")
    class AuthZ {

        @Test
        @DisplayName("When created, Then httpStatus 403")
        void givenAuthz_whenHttpStatus_then403() {
            A2AuthorizationException ex = new A2AuthorizationException("forbidden");
            assertEquals(403, ex.httpStatus());
        }
    }
}
