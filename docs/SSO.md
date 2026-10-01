# A2 SSO — Google, Entra, Okta, Ping, Active Directory, Auth0

A2 treats major identity providers as **first-class SSO annotations**. Under the hood they use OIDC discovery + JWKS (or Kerberos / SAML for on-prem AD).

## Annotations

| Annotation | IdP | Typical issuer |
|------------|-----|----------------|
| `@A2GoogleSso` | Google / Gmail / Workspace | `https://accounts.google.com` |
| `@A2EntraSso` | Microsoft Entra ID | `https://login.microsoftonline.com/{tenant}/v2.0` |
| `@A2OktaSso` | Okta | `https://{domain}.okta.com/oauth2/default` |
| `@A2PingSso` | PingOne / PingFederate | your issuer URL |
| `@A2ActiveDirectorySso` | On-prem AD / AD FS | Kerberos, SAML, or OIDC |
| `@A2Auth0Sso` | Auth0 | `https://{domain}` |
| `@A2Sso` | Generic | any issuer |

## Dependency

```xml
<dependency>
  <groupId>io.a2</groupId>
  <artifactId>a2-provider-sso</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Register providers at startup

```java
import io.a2.core.A2Runtime;
import io.a2.provider.sso.SsoProviderFactory;
import io.a2.provider.sso.SsoProtocolProvider;

SsoProtocolProvider okta = SsoProviderFactory.okta(
    "mycompany.okta.com", "0oa…", System.getenv("OKTA_CLIENT_SECRET"));
SsoProviderFactory.register(A2Runtime.get(), okta);

SsoProtocolProvider google = SsoProviderFactory.google(
    "….apps.googleusercontent.com", System.getenv("GOOGLE_CLIENT_SECRET"), "company.com");
SsoProviderFactory.register(A2Runtime.get(), google);

SsoProtocolProvider entra = SsoProviderFactory.entra(
    "tenant-guid-or-common", "app-client-id", System.getenv("ENTRA_CLIENT_SECRET"));
SsoProviderFactory.register(A2Runtime.get(), entra);
```

Named registration lets several IdPs coexist: `A2Runtime.get().namedProvider("okta")`.

## Protect endpoints

```java
@A2OktaSso(domain = "mycompany.okta.com", clientId = "0oa…", roles = {"Everyone"})
public class EmployeeApi { … }

@A2GoogleSso(clientId = "….apps.googleusercontent.com",
             hostedDomain = "company.com", roles = {"user"})
public void gmailOnly() { … }

@A2EntraSso(tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            clientId = "app-id", roles = {"Employee"})
public void corporate() { … }

@A2PingSso(issuer = "https://auth.pingone.com/env/as", clientId = "…")
public void pingProtected() { … }

@A2ActiveDirectorySso(mode = A2ActiveDirectorySso.AdMode.KERBEROS,
                      realm = "CORP.EXAMPLE.COM",
                      servicePrincipal = "HTTP/app.corp.example.com")
public void intranet() { … }

@A2Auth0Sso(domain = "myapp.us.auth0.com", clientId = "…", audience = "https://api.example.com")
public void auth0Api() { … }
```

Client sends: `Authorization: Bearer <access-or-id-token>` issued by that IdP.

## Active Directory modes

| Mode | Mechanism | Module |
|------|-----------|--------|
| `KERBEROS` | SPNEGO / GSS | `a2-provider-kerberos` |
| `SAML` | AD FS assertions | `a2-provider-saml` |
| `OIDC` | AD FS / Entra hybrid | `a2-provider-sso` |
| `LDAP` | simple bind (legacy) | configure externally |

Full guide: this document is the SSO section of the A2 framework.
