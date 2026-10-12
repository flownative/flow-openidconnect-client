# Upgrading from 6.0 to 6.1

Version 6.1 adds features and needs no configuration changes. Nothing
was removed or renamed, and there are no new required settings. Three
changes can still make an application behave differently after the
update, so check them before you deploy.

## Overview

| Change                                                    | Action is needed if …                                                                                         |
|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| [Authorized party](#authorized-party)                     | your application accepts tokens which carry the client id in their audience, but were issued to other clients |
| [Scopes in identity tokens](#scopes-in-identity-tokens)   | your code calls `IdentityToken::scopeContains()`                                                              |
| [Time limits for requests](#time-limits-for-requests)     | your identity provider takes longer than 5 seconds to connect or 10 seconds to answer                         |
| [Client credentials](#client-credentials)                 | your code calls `OpenIdConnectClient::getAccessToken()`, or you use `./flow oidc:getAccessToken`              |
| [Further changes](#further-changes)                       | you rely on details of key reloading, discovery or error handling                                             |

## Authorized Party

The provider now checks the "azp" claim, as OpenID Connect Core 1.0,
section 3.1.3.7, asks for. Version 6.0 didn't check it at all.

For every token whose "aud" claim contains the client id of the
service, a token is rejected if

- it has several audiences and no "azp" claim, or
- its "azp" claim is not the client id.

This applies with and without the "audience" option, in the JWT mode,
in the session mode and to bearer tokens. Tokens whose audience doesn't
contain the client id are not affected. Rejected tokens lead to wrong
credentials, and the security log contains "Rejected the identity
token" together with "authorized party".

Applications which accept access tokens for an API can be affected if
the identity provider puts the client id itself into the audience. An
example is Microsoft Entra ID, if the API is the same app registration
as the client and has no Application ID URI of its own. Access tokens
which other clients obtained for such an API name these clients in
"azp" and are now rejected. Give the API an identifier of its own, for
example an Application ID URI like "api://…", and configure it as
"audience" of the provider:

```yaml
providerOptions:
  audience: 'api://my-application'
```

## Scopes in Identity Tokens

`IdentityToken::scopeContains()` now splits the "scope" claim at
whitespace, as OAuth 2.0 defines it. Version 6.0 split it at commas.
The method also reads the "scp" claim, as a string or as a list, which
identity providers like Microsoft Entra ID use instead.

- Code which relied on comma-separated scopes, like "read,write", now
  receives false.
- Code which received false for space-separated scopes, like "read
  write", now receives true.

The package itself doesn't call this method, so only your own code is
affected. Check every call of it, because it usually decides about
permissions.

## Time Limits for Requests

All requests which the client sends to the identity provider now use an
HTTP client with time limits: discovery, the key set, the code exchange,
refreshing tokens and client credentials. Only the command
`./flow oidc:discover` still waits without a limit. A request fails if no connection is made within
5 seconds, or if the answer takes longer than 10 seconds in total.
Version 6.0 waited without a limit.

If your identity provider is slower, raise the limits:

```yaml
Flownative:
  OpenIdConnect:
    Client:
      httpClient:
        connectTimeout: 5
        timeout: 10
```

Both settings take a positive number of seconds. Any other value makes
the factory of the HTTP client fail with a RuntimeException when it is
created.

The client comes from `HttpClientFactoryInterface`, which
`Configuration/Objects.yaml` binds to `HttpClientFactory`. Replace the
implementation to send the requests through a proxy, or in your tests.
A factory of your own must keep the verification of TLS certificates
switched on, see "Requests to the Identity Provider" in the README.

## Client Credentials

`OpenIdConnectClient::getAccessToken()` is deprecated. It still works
as before. Use `getClientCredentialsAccessToken()` instead:

```php
// Before
$accessToken = $client->getAccessToken('myService', $clientId, $clientSecret, 'billing', ['audience' => 'https://api.example.com']);

// After
$accessToken = $client->getClientCredentialsAccessToken('billing');
```

The new method uses the service of the client and takes the client id
and secret, and the "additionalParameters", from the configuration of
the service:

```yaml
Flownative:
  OpenIdConnect:
    Client:
      services:
        myService:
          options:
            clientId: 'abcdefghijklmnopqrstuvwxyz01234567890'
            clientSecret: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5MA=='
            additionalParameters:
              audience: 'https://api.example.com'
```

Both arguments are optional. With an empty scope, the identity
provider uses its default scope. Parameters which you pass as second
argument replace configured parameters of the same name. If the client
id or the secret is empty, the method throws a
`ConfigurationException`.

The command `./flow oidc:getAccessToken` now uses this method as well.

## Further Changes

These changes need no action in most applications:

- If a token names a key identifier ("kid") which the cached key set
  doesn't contain, and claims to come from the expected issuer, the
  client loads the key set again, at most once per minute. Rotated keys
  therefore need no cache flush. A key set without an array in "keys"
  now leads to a `ServiceException`.
- The client reads the "end_session_endpoint" of the discovery document.
  An "endSessionEndpoint" option which is not an absolute http(s)
  address makes the creation of the client fail with a
  `ConfigurationException`. The discovery cache doesn't need to be
  flushed.
- `refreshIdentityToken()` takes the client id and secret from the
  options of the client instead of the raw settings. The values are the
  same, because the options are the settings of the service, merged
  with the discovery document.
- Token arguments in the return from the identity provider which are
  too short to contain an HMAC now count as wrong credentials, instead
  of causing an uncaught exception.
- `OpenIdConnectToken` now extends `AbstractOpenIdConnectToken`, which
  holds the constants and methods it shares with the new session token.
  They are still available on `OpenIdConnectToken`.

## New Features

All new features are opt-in and described in the README:

- Session mode with persisted accounts: `OpenIdConnectSessionToken`,
  the provider options "accountResolver" and "lookupProviderName",
  `AccountResolverInterface` and `PersistedAccountResolver`
- Signing out at the identity provider: `buildEndSessionUri()`, the
  service option "endSessionEndpoint" and `IdentityTokenOfLogin`
- Entry point options "authorizationParameters" and
  "loginFailedRedirectUri", and a fifth argument
  `$authorizationParameters` of `startAuthorization()`
- Validating tokens in your own code: `IdentityTokenValidator`,
  `IdentityTokenRequirements`, `ValidatedIdentityToken`,
  `IdentityTokenRejectedException` and `ExpiredIdentityTokenException`
- `HttpClientFactoryInterface` for the HTTP client, see above

## Checklist

1. Search your code for `scopeContains(` and check which format the
   scopes of your tokens have.
2. If your application accepts access tokens for an API, check whether
   their audience contains the client id, and whether "azp" names
   another client. After the update, search the security log for
   "authorized party".
3. If your identity provider is slow or far away, set the time limits.
4. Replace calls of `getAccessToken()` with
   `getClientCredentialsAccessToken()`.
