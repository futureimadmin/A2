package io.a2.spring;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("A2Properties — GivenWhenThen")
class A2PropertiesGwtTest {

    @Nested
    @DisplayName("Given default A2Properties")
    class Defaults {

        @Test
        @DisplayName("When constructed, Then auth and cors nested objects non-null with safe defaults")
        void givenDefaults_whenConstructed_thenNestedPresent() {
            A2Properties props = new A2Properties();
            assertNotNull(props.getAuth());
            assertNotNull(props.getCors());
            assertTrue(props.getAuth().isFilterEnabled());
            assertTrue(props.getCors().isEnabled());
            assertTrue(props.getCors().getAllowedMethods().contains("OPTIONS"));
        }

        @Test
        @DisplayName("When auth filter disabled, Then isFilterEnabled false")
        void givenAuthDisabled_whenSet_thenFalse() {
            A2Properties props = new A2Properties();
            props.getAuth().setFilterEnabled(false);
            assertFalse(props.getAuth().isFilterEnabled());
        }

        @Test
        @DisplayName("When cors origins set, Then list reflects values")
        void givenCorsOrigins_whenSet_thenReadable() {
            A2Properties props = new A2Properties();
            props.getCors().setAllowedOrigins(java.util.List.of("https://app.example.com"));
            assertEquals(1, props.getCors().getAllowedOrigins().size());
            assertEquals("https://app.example.com", props.getCors().getAllowedOrigins().get(0));
        }
    }
}
