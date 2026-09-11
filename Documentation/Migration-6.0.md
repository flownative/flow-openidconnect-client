# Migrating from 5.x to 6.0

Version 6.0 requires current versions of PHP and Flow, and it makes
authentication considerably stricter. Many applications only need to
adjust their configuration, and some need no changes at all.

This guide lists every change which may require action and explains how
to find out whether your application is affected. Start with the
overview, then read the sections which apply to your application.

Users have to log in once more after the update, because the JWT cookie
has a new default name and refresh tokens stored by version 5 are no
longer used.

## Overview

| Change                                                        | Action is needed if …                                                                                           |
|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| [Requirements](#requirements)                                 | your application runs on PHP 8.1 or 8.2, or on Flow 7 or 8                                                      |
| [Token validation](#token-validation)                         | you accept access tokens for an API, don't use discovery, or your identity provider uses an unexpected issuer   |
| [Email as account identifier](#email-as-account-identifier)   | the claim "email" identifies your accounts                                                                      |
| [JWT cookie](#jwt-cookie)                                     | JavaScript or a proxy reads the JWT cookie, or you rely on its name                                             |
| [Bearer tokens](#bearer-tokens)                               | clients rely on a cookie or a server-side refresh after sending a bearer token                                  |
| [Login binding](#login-binding)                               | your code calls `OpenIdConnectClient::startAuthorization()`, or the login runs in a cross-site iframe            |
| [Rejected logins](#rejected-logins)                           | users can end up with a rejected login, for example with an unverified email address                            |
| [Status 401 for scripts](#status-401-for-scripts-and-api-clients) | your frontend loads content with XHR, fetch or HTMX                                                         |
| [Refresh tokens](#refresh-tokens)                             | your code calls `OpenIdConnectClient::refreshIdentityToken()`                                                   |
| [Changed APIs](#changes-for-code-which-uses-the-package-directly) | your code uses classes of this package directly                                                              |

## Requirements

- PHP 8.3, 8.4 or 8.5
- Flow 9.0 or later
- flownative/oauth2-client 5.0
- lcobucci/jwt 5.6 and Guzzle 7.9

lcobucci/jwt only matters if your own code uses this library directly,
because its API changed between version 4 and 5.

## Token Validation

The authentication provider now validates tokens as described in OpenID
Connect Core 1.0, section 3.1.3.7. A token is only accepted if

- its signature is valid,
- it was issued by the expected issuer ("iss"),
- it was issued for the expected audience ("aud"),
- it is not expired ("exp") and already valid ("nbf", "iat"), and
- the claim used as account identifier is present.

Tokens without an expiration time are treated as expired. A rejected
token leads to wrong credentials, and the reason is written to the
security log.
After the update, search the security log for "Rejected the identity
token" to find tokens which are no longer accepted.

### Issuer

The expected issuer is taken from the discovery document of the service.
If the service is configured without "discoveryUri", set its "issuer"
option:

```yaml
Flownative:
  OpenIdConnect:
    Client:
      services:
        myService:
          options:
            issuer: 'https://id.example.com/'
            jwksUri: 'https://id.example.com/.well-known/jwks.json'
```

Some identity providers issue tokens with a different issuer than the
one in their discovery document, for example version 1 access tokens of
Microsoft Entra ID. Set the expected issuer in the provider options
then. It may be a list, and it may contain the placeholder "{tenantid}"
for multi-tenant applications of Microsoft Entra ID:

```yaml
providerOptions:
  issuer:
    - 'https://login.microsoftonline.com/{tenantid}/v2.0'
    - 'https://sts.windows.net/{tenantid}/'
```

### Audience

A token must contain the client id of the service in its "aud" claim.
Identity tokens issued for your application do. Access tokens for an API
usually carry the identifier of the API instead, so an application which
accepts access tokens must configure the expected audience:

```yaml
providerOptions:
  audience: 'https://api.example.com'
```

In version 5, the audience was only checked if this option was set.

### Clock Leeway

Time claims are checked with a leeway of 60 seconds, which compensates
for clock differences between your application and the identity
provider. Change it with the "leeway" provider option.

### Signing Keys

Signatures are verified with RSA keys and the algorithms RS256, RS384 and
RS512. If a token names a key identifier ("kid"), only the key with this
identifier is used. Keys whose "use", "key_ops" or "alg" don't allow
verifying a signature with the algorithm of the token are ignored.
Tokens with critical header extensions ("crit") are rejected.

## Email as Account Identifier

If "accountIdentifierTokenValueName" is "email", a token is only
accepted if its "email_verified" claim is true. Otherwise, the security
log contains "is not verified".

This affects identity providers which don't send the claim, and users
whose address the identity provider has not verified, for example users
created by an administrator. Microsoft Entra ID doesn't verify its
"email" claim at all.

Prefer a claim which the identity provider controls and which never
changes for a user: "sub", or "oid" for Microsoft Entra ID. Only if your
identity provider verifies all email addresses without sending the
claim, disable the check:

```yaml
providerOptions:
  accountIdentifierTokenValueName: 'email'
  requireVerifiedEmail: false
```

With "addRolesFromExistingAccount", the identifier in the token must now
match the identifier of the existing account exactly, apart from upper
and lower case.

## JWT Cookie

### Scripts Can't Read the Cookie

The JWT cookie is now "httpOnly", so JavaScript can't read the identity
token from it. If your frontend needs to read it, disable the flag.
Every script on your pages can then read the token, including injected
ones.

```yaml
Flownative:
  OpenIdConnect:
    Client:
      middleware:
        cookie:
          httpOnly: false
```

### New Cookie Names

With "secure" enabled, which is the default, the JWT cookie is named
"__Host-flownative_oidc_jwt". Browsers only accept a cookie with this
prefix if the site itself sets it over HTTPS, so that another subdomain
can't plant a cookie with a login of its own.

- A name configured with "jwtCookieName" or "cookie.name" is used as it
  is. Consider giving it the prefix, for example
  "__Host-flownative_oidc_jwt".
- If a proxy or other code reads the cookie by its name, update the
  name.
- Browsers reject the prefix without "secure", so the names have no
  prefix if you set "cookie.secure" to false for testing without HTTPS.
- The provider now reads the cookie name configured in "cookie.name" as
  well. The deprecated options "secureCookie" and "cookieName" still
  work and now apply everywhere.

Flow's session cookie can get the prefix too, if your site is only
served over HTTPS. Changing the name ends all existing sessions once:

```yaml
Neos:
  Flow:
    session:
      name: '__Host-Neos_Flow_Session'
      cookie:
        secure: true
```

### Caching

The middleware renews the JWT cookie with every response to a logged-in
user. These responses, and responses which remove the cookie, are now
marked as private for HTTP caches: "public" and "s-maxage" are removed,
"no-store" is added to responses with "no-cache", and the headers
"CDN-Cache-Control" and "Surrogate-Control" are removed.

## Bearer Tokens

Requests with a token in the "Authorization" header neither set nor
remove the JWT cookie anymore, and their expired tokens are not
refreshed on the server.

If a client relied on the cookie which it received after sending a
bearer token, for example to load images or downloads, it must send the
header with these requests as well, or use the regular login. Clients
which send bearer tokens must refresh them themselves.

## Login Binding

The entry point binds each login to the browser which started it. It
stores a random secret in a cookie named "__Host-flownative_oidc_nonce_…"
and sends a hash of it as "nonce" to the identity provider. When the
browser returns, the identity token must contain this nonce, and the
browser must still have the cookie.

- Your identity provider must return the nonce in the identity token, as
  OpenID Connect requires. If it doesn't, every login fails and the
  security log contains "contains no nonce".
- The cookie has "SameSite=Lax". Browsers don't send it to a login which
  runs in an iframe on another site, so such a login fails with "not
  started in this browser" in the security log.
- Logins which are in progress while you deploy the update fail once,
  see [Rejected logins](#rejected-logins).

### Code Which Starts an Authorization

`OpenIdConnectClient::startAuthorization()` now requires a nonce as third
argument. The response which redirects the browser must set the cookie
of the nonce and must not be cached, because the cookie contains the
secret:

```php
use Flownative\OpenIdConnect\Client\Authentication\Nonce;
use Flownative\OpenIdConnect\Client\CookieSettings;
use Flownative\OpenIdConnect\Client\OpenIdConnectClientFactory;
use GuzzleHttp\Psr7\Uri;

#[Flow\Inject]
protected OpenIdConnectClientFactory $openIdConnectClientFactory;

#[Flow\InjectConfiguration(path: 'middleware', package: 'Flownative.OpenIdConnect.Client')]
protected array $middlewareSettings = [];

public function loginAction(): void
{
    $client = $this->openIdConnectClientFactory->create('myService');
    $nonce = Nonce::generate();
    $uri = $client->startAuthorization(new Uri('https://www.example.com/dashboard'), 'profile email', $nonce);

    $this->response->setCookie($nonce->createCookie(CookieSettings::fromMiddlewareSettings($this->middlewareSettings)));
    $this->response->setHttpHeader('Cache-Control', 'no-store');
    $this->redirectToUri($uri);
}
```

## Rejected Logins

If the application rejects a login when the browser returns from the
identity provider, the entry point no longer starts another login. The
identity provider would usually send the user back right away without
asking, and the login would be rejected again, which ended in an
endless redirect loop. Reasons are, for example, an unexpected audience,
an unverified email address or a missing nonce cookie.

The entry point now answers with status 403 and a short "Login failed"
page with a link to try again. The security log contains "was rejected
when the browser returned" together with the reason of the rejection.

## Status 401 for Scripts and API Clients

The entry point now only redirects browsers which navigate to a page.
The following requests receive status 401 with "WWW-Authenticate:
Bearer" instead:

- requests with a bearer token in the "Authorization" header
- XHR requests with "X-Requested-With: XMLHttpRequest"
- requests whose "Sec-Fetch-Mode" header is not "navigate", for example
  fetch or HTMX requests

In version 5, these requests received a redirect to the identity
provider, which scripts can't follow. If your frontend loads content
with XHR, fetch or HTMX, handle status 401, for example by reloading the
page, which then starts the login.

## Refresh Tokens

- After a login, the session gets a new identifier.
- Each authentication provider keeps its refresh token under its own key
  in the session.
- The refresh token is bound to the identity token which was issued
  last, and only this identity token is refreshed. For ten minutes
  after a refresh, requests which still carry the previous identity
  token receive the refreshed one from the session.
- A refreshed identity token must have the same issuer and subject as
  the expired one.
- If the identity provider rotates refresh tokens, the new refresh token
  replaces the old one. In version 5, each refresh after the first one
  failed with such identity providers.
- The refresh request no longer sends "prompt" and "id_token_hint".
- Refreshing no longer starts a session.
- Refresh tokens stored by version 5 are ignored, so users log in once
  more when their identity token expires.

## Changes for Code Which Uses the Package Directly

| Version 5                                                            | Version 6                                                                                                  |
|----------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| `new OpenIdConnectClient($serviceName)`                              | still works, but inject `OpenIdConnectClientFactory` and call `create($serviceName)` to keep code testable |
| `TokenArguments::fromArray($arguments)`                              | `TokenArguments::fromArray($arguments, $hashService)`                                                      |
| `TokenArguments::fromSignedString($string)`                          | `TokenArguments::fromSignedString($string, $hashService)`                                                  |
| `startAuthorization($returnToUri, $scope, $requestRefreshToken)`     | `startAuthorization($returnToUri, $scope, $nonce, $requestRefreshToken)`                                   |
| `refreshIdentityToken($identityToken, $refreshToken)`                | `refreshIdentityToken($refreshToken)`                                                                      |
| `IdentityToken::isExpiredAt()` returns false for tokens without "exp" | returns true                                                                                              |

## Log Messages

Rejected logins and tokens are written to the security log with the
reason. These messages help to find configuration problems after the
update:

| Message contains                              | Meaning                                                                             |
|-----------------------------------------------|-------------------------------------------------------------------------------------|
| "Rejected the identity token"                 | the token failed a check; the message names the issuer, audience or claim           |
| "is not verified"                             | "email" identifies the account, but "email_verified" is not true                    |
| "contains no nonce"                           | the identity provider didn't return the nonce of the login                          |
| "not started in this browser"                 | the nonce cookie is missing, for example because the login ran in a cross-site iframe |
| "belongs to another identity token"           | the session holds a refresh token for another identity token, so nothing is refreshed |
| "was rejected when the browser returned"      | the entry point showed the "Login failed" page instead of starting another login     |
