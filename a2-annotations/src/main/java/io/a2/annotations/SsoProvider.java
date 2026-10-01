package io.a2.annotations;

/**
 * Known SSO / identity-provider brands supported by A2 out of the box.
 * Each maps to well-known OIDC discovery (or Kerberos/SAML for on-prem AD).
 */
public enum SsoProvider {
    /** Google / Gmail / Google Workspace (accounts.google.com). */
    GOOGLE,
    /** Microsoft Entra ID (formerly Azure AD). */
    ENTRA,
    /** Okta. */
    OKTA,
    /** Ping Identity / PingFederate. */
    PING,
    /** On-premises Active Directory (Kerberos, SAML federation, or LDAP bind). */
    ACTIVE_DIRECTORY,
    /** Auth0. */
    AUTH0,
    /** Keycloak. */
    KEYCLOAK,
    /** Any other IdP — supply issuer / discovery URI explicitly. */
    CUSTOM
}
