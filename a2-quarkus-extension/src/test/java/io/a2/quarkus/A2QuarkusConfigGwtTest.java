package io.a2.quarkus;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("A2 Quarkus extension — GivenWhenThen")
class A2QuarkusConfigGwtTest {

    @Nested
    @DisplayName("Given extension classes on classpath")
    class Classpath {

        @Test
        @DisplayName("When A2QuarkusConfig loaded, Then class is present")
        void givenConfigClass_whenLoaded_thenPresent() {
            assertDoesNotThrow(() -> Class.forName("io.a2.quarkus.A2QuarkusConfig"));
        }

        @Test
        @DisplayName("When A2AuthFilter loaded, Then class is present")
        void givenAuthFilter_whenLoaded_thenPresent() {
            assertDoesNotThrow(() -> Class.forName("io.a2.quarkus.A2AuthFilter"));
        }

        @Test
        @DisplayName("When A2ExceptionMapper loaded, Then class is present")
        void givenExceptionMapper_whenLoaded_thenPresent() {
            assertDoesNotThrow(() -> Class.forName("io.a2.quarkus.A2ExceptionMapper"));
        }

        @Test
        @DisplayName("When A2SecurityInterceptor loaded, Then class is present")
        void givenSecurityInterceptor_whenLoaded_thenPresent() {
            assertDoesNotThrow(() -> Class.forName("io.a2.quarkus.A2SecurityInterceptor"));
        }
    }
}
