package io.a2.spi;

import io.a2.spi.model.InstantCredentialsRequest;
import io.a2.spi.model.TokenResult;

/**
 * A2 unified short-lived credential issuer (max 1 hour).
 * Covers Assume Role, Impersonation (source → target), and service credentials.
 */
public interface InstantCredentialsService {

    TokenResult issue(InstantCredentialsRequest request);
}
