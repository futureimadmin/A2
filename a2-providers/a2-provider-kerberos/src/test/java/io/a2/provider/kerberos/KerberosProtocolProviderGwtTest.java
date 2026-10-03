package io.a2.provider.kerberos;

import io.a2.annotations.Protocol;
import io.a2.spi.model.AuthRequest;
import io.a2.spi.model.AuthResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("KerberosProtocolProvider — GivenWhenThen")
class KerberosProtocolProviderGwtTest {

    @Nested
    @DisplayName("Given default Kerberos provider")
    class Defaults {

        @Test
        @DisplayName("When id(), Then KERBEROS")
        void givenProvider_whenId_thenKerberos() {
            KerberosProtocolProvider p = new KerberosProtocolProvider();
            assertEquals(Protocol.KERBEROS, p.id());
        }

        @Test
        @DisplayName("When authenticate with empty credentials, Then failure")
        void givenEmptyCreds_whenAuthenticate_thenFailure() {
            KerberosProtocolProvider p = new KerberosProtocolProvider();
            AuthResult r = p.authenticate(AuthRequest.builder()
                    .protocol(Protocol.KERBEROS)
                    .credentials("")
                    .build());
            assertFalse(r.isSuccess());
        }

        @Test
        @DisplayName("When authenticate with null credentials, Then failure")
        void givenNullCreds_whenAuthenticate_thenFailure() {
            KerberosProtocolProvider p = new KerberosProtocolProvider();
            AuthResult r = p.authenticate(AuthRequest.builder()
                    .protocol(Protocol.KERBEROS)
                    .build());
            assertFalse(r.isSuccess());
        }
    }
}
