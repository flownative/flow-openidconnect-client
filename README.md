[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)
[![Packagist](https://img.shields.io/packagist/v/flownative/openidconnect-client.svg)](https://packagist.org/packages/flownative/openidconnect-client)
![Tests](https://github.com/flownative/flow-openidconnect-client/workflows/CI/badge.svg?branch=master)
[![Maintenance level: Love](https://img.shields.io/badge/maintenance-%E2%99%A1%E2%99%A1%E2%99%A1-ff69b4.svg)](https://www.flownative.com/en/products/open-source.html)

# OpenID Connect Client for Flow Framework

This [Flow](https://flow.neos.io) package provides an
[OpenID Connect](https://openid.net/connect/) (OIDC) client SDK. OpenID
Connect is an authentication layer built on top of OAuth 2.0. While
OAuth is intended to be used for *authorization*, OpenID Connect is
responsible for *authentication* – that is, verifying the identity of a
human or machine user, commonly called "entity".

OIDC provides profile information about an authenticated user through an
*identity token*, which is encoded as a secure JSON Web Token (JWT).
JWTs are easy to handle in client- and server-side applications. The
data contained in the ID token is usually signed and can optionally be
encrypted.

## Feature Overview

This plugin acts as a Flow authentication provider. It allows you to
authenticate and authorize users using a browser and machine users (for
example, other applications) communicating with your application via an
API.

A few feature highlights of this package:

- drop-in replacement for other authentication methods for Flow
  applications or Neos websites
- OIDC auto-discovery support for minimal configuration
- support for multiple OIDC services (servers) within one application
- integration into Flow's session management based on JWT cookies
- mapping of Flow user roles from claims
- automatic JWT signature verification
- authentication via bearer access token
- automatic refresh of expired access tokens
- easy access to ID tokens through the Flow account model
- command line support for testing

## Terms and Background

Before deploying OpenID Connect for your application, you should get
familiar with the concepts. As a quick reminder, here are some terms you
should know about.

### Authentication vs. Authorization

Authentication is the process of confirming the identity of a person or
other entity. A user will need to proof her identity – for example by
providing a username and password.

Authorization refers to the process of verifying what actions entities
are allowed to perform or which information they may access. In this
cases it's not about the identity, but only about the permissions.

More often than not, you will want to combine these concepts for your
application – but it's important to know the difference.

### Identity Provider

An Identity Provider is handling the authentication and authorization
process for you. Popular identity providers are Google, Facebook,
Microsoft, paid services like [Auth0](https://auth0.com/), or dedicated
setups like [gluu](https://www.gluu.org/). Identity providers may
implement methods like username / password authentication or advanced
methods, like multi-factor authentication.

### Identity Token

The ID Token is provided as part of a JSON Web Token (JWT). It contains
the identity data of the authenticated entity. A JWT consists of a
header, body and signature.

### Claims

The ID Token provides information about an entity (for example, a user).
The different bits of information could be a name, a URL pointing to a
profile picture or an email address. These information bits are called
"claims". And because they are signed, as part of the JWT, you can trust
them without having to specifically ask a central API.

### Bearer Access Token

The access token gives the holder access to a specific service or other
resource. That means, whoever owns this access token is permitted to
access the resources for which the token was issued.

Access tokens usually have a limited lifetime and are issued for a
specific scope.

## Requirements

In order to use this plugin you need:

- an OIDC Identity Provider which provides auto discovery
- an application (such as Neos), based on Flow 6.0 or higher

## Installation

The Flownative OpenID Connect plugin is installed via Composer:

```
composer require flownative/openidconnect-client
```

## Usage Scenarios

Here are a few examples for using this plugin:

### Authenticate web users

For example, use this plugin to authenticate and authorize users for the
Neos backend.

What you need is:

- configure the discovery URI for your identity provider
- configure Flow to use this plugin as an authentication provider
- configure the HTTP chain to manage JWT session cookies
- configure Flow and this plugin to set user roles

You will use the
[Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1)
for this type of application.

### Authenticate applications

For example, use this plugin to authenticate and authorize your other
third party's services accessing an API provided by your application.

- configure the discovery URI for your identity provider
- configure Flow to use this plugin as a (second) authentication
  provider
- configure the HTTP chain to manage JWT session cookies
- configure Flow and this plugin to set user roles
- protect your API methods and evaluate further permissions obtained
  from the identity token

You will use the
[Client Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.4)
for this type of application.

## OpenID Connect Discovery

Identity providers usually expose OIDC discovery documents at a certain
URL (for example,
*https://id.example.com/.well-known/openid-configuration*). The
Flownative OIDC client plugin uses discovery to configure authorization,
token and user info endpoints, the JWKs location, supported scopes and
more.

Configure the discovery endpoint as follows:

```yaml
Flownative:
  OpenIdConnect:
    Client:
      services:
        myService:
          options:
            discoveryUri: 'https://id.example.com/.well-known/openid-configuration'            
 ```

You can check if discovery is working by running the following command
from a terminal:

```
./flow oidc:discover myService

+---------------------------------------+-----------------------------------------------------------+
| Option                                | Value                                                     |
+---------------------------------------+-----------------------------------------------------------+
| issuer                                | https://id.example.com/                                   |
| authorization_endpoint                | https://id.example.com/authorize                          |
| token_endpoint                        | https://id.example.com/oauth/token                        |
| userinfo_endpoint                     | https://id.example.com/userinfo                           |
| mfa_challenge_endpoint                | https://id.example.com/mfa/challenge                      |
| jwks_uri                              | https://id.example.com/.well-known/jwks.json              |
| registration_endpoint                 | https://id.example.com/oidc/register                      |
| revocation_endpoint                   | https://id.example.com/oauth/revoke                       |
| scopes_supported                      | array (                                                   |
|                                       |   0 => 'openid',                                          |
|                                       |   1 => 'profile',                                         |
|                                       |   2 => 'offline_access',                                  |
|                                       |   3 => 'name',                                            |
|                                       |   4 => 'given_name',                                      |
|                                       |   5 => 'family_name',                                     |
|                                       |   6 => 'nickname',                                        |
|                                       |   7 => 'email',                                           |
|                                       |   8 => 'email_verified',                                  |
|                                       |   9 => 'picture',                                         |
|                                       |   10 => 'created_at',                                     |
|                                       |   11 => 'identities',                                     |
|                                       |   12 => 'phone',                                          |
|                                       |   13 => 'address',                                        |
|                                       | )                                                         |
| response_types_supported              | array (                                                   |
|                                       |   0 => 'code',                                            |
|                                       |   1 => 'token',                                           |
|                                       |   2 => 'id_token',                                        |
|                                       |   3 => 'code token',                                      |
|                                       |   4 => 'code id_token',                                   |
|                                       |   5 => 'token id_token',                                  |
|                                       |   6 => 'code token id_token',                             |
|                                       | )                                                         |
| code_challenge_methods_supported      | array (                                                   |
|                                       |   0 => 'S256',                                            |
|                                       |   1 => 'plain',                                           |
|                                       | )                                                         |
| response_modes_supported              | array (                                                   |
|                                       |   0 => 'query',                                           |
|                                       |   1 => 'fragment',                                        |
|                                       |   2 => 'form_post',                                       |

…

```

## Authorization Code Grant

The Authorization Code Grant is used for authenticating users using a
web browser. The typical application flow goes like this:

1. a user tries to access a protected page (controller action)
2. Flow checks if the user has a cookie containing a valid JWT
3. no valid JWT, so redirect to the identity provider's login page
4. user logs in and is redirected back to Flow
5. an authorization code is passed to Flow and Flow uses that to obtain
   an access token behind the scenes
6. a JWT is extracted from the access token and sent to the browser as a
   cookie
7. during the following web requests, the browser sends the cookie and Flow
   recognizes the user as being authenticated

The Flow application needs a client identifier and a client secret so it
can request authorization codes from the identity provider.

Here's an example configuration which enables OIDC authentication for a
Neos backend. Please note that this is a proof-of-concept. This
integration needs further configuration and custom implementation to be
production-ready:

```yaml
Flownative:
  OpenIdConnect:
    Client:
      services:
        test:
          options:
            discoveryUri: 'https://id.example.com/.well-known/openid-configuration'
            clientId: 'abcdefghijklmnopqrstuvwxyz01234567890'
            clientSecret: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5MA=='

Neos:
  Flow:
    http:
      chain:
        'postprocess':
          chain:
            'Flownative.OpenIdConnect.Client:setJwtCookie':
              componentOptions:
                authenticationProviderName: 'Neos.Neos:Backend'
                cookie:
                  # For testing purposes allow cookies without HTTPS:
                  secure: false

    security:
      authentication:
        providers:
          # Re-use the Neos authentication provider so we automatically get the right
          # request patterns:
          'Neos.Neos:Backend':
            label: 'Neos Backend (OIDC)'
            provider: 'Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectProvider'
            providerOptions:
              roles: ['Neos.Neos:Administrator']
              accountIdentifierTokenValueName: 'sub'
              serviceName: 'test'
            token: 'Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken'
            entryPoint: 'Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectEntryPoint'
            entryPointOptions:
              serviceName: 'test'
              scopes: ['sub', 'profile', 'name']

        authenticationStrategy: atLeastOneToken

```

Without further programming you need to manually create a Neos user which
has the same username like the one provided in the "sub" claim by the
OIDC identity provider.

## Client Credentials Grant

Client Credentials Grant is a bit simpler than Authorization Code Grant,
but can only be used for trusted parties. Because you use long-living
client credentials directly (instead of going that extra step of trading
an access token for an authorization code), you cannot use this type of
grant in a browser, because the credentials would not be safe there.

Here's an example consisting of two parts: An application providing an
API and a second one consuming that API.  
 
The URI used as the "audience" string is only a URI by convention. In
fact, it can be any other string, but must be recognized by your
identity provider.

The following configuration is used in the Flow application *using* the
API:

```yaml
Flownative:
  OpenIdConnect:
    Client:
      services:
        test:
          options:
            discoveryUri: 'https://id.example.com/.well-known/openid-configuration'
            clientId: 'abcdefghijklmnopqrstuvwxyz01234567890'
            clientSecret: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5MA=='
            additionalParameters:
              audience: 'http://yourapp.localbeach.net/api/v1'
```

Somewhere in your application you might have a service class which wraps
communication with the API. It may look like this (some code omitted for
brevity):

```php
class BillingService
{
    public function sendAuthenticatedRequest(string $relativeUri, string $method = 'GET', array $bodyFields = []): ResponseInterface
    {
        $openIdConnectClient = new OpenIdConnectClient('test');

        $accessToken = $openIdConnectClient->getAccessToken(
            'test',
            $this->clientId,
            $this->clientSecret,
            '',
            Authorization::GRANT_CLIENT_CREDENTIALS,
            $this->additionalParameters
        );

        $httpClient = new Client(['allow_redirects' => false]);
        return $httpClient->request(
            $method,
            trim($this->apiBaseUri, '/') . '/' . $relativeUri,
            [
                'headers' =>
                    [
                        'Content-Type' => 'application/json',
                        'Authorization' => 'Bearer ' . $accessToken->getToken()
                    ],
                'body' => ($bodyFields !== [] ? \GuzzleHttp\json_encode($bodyFields) : '')
            ]
        );
    }
}
```

The important bit is that your code uses the OpenID Connect Client to
retrieve an access token and then sends that as part of an authorization
header to the API.

The application *providing* the API needs the following configuration,
likely using a different client id and secret than the consuming app:

```yaml
Flownative:
  OpenIdConnect:
    Client:
      services:
        test:
          options:
            discoveryUri: 'https://id.example.com/.well-known/openid-configuration'
            clientId: 'abcdefghijklmnopqrstuvwxyz01234567890'
            clientSecret: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5MA=='
```

A base controller in your application providing the API may look like
this:

```php
abstract class AbstractApiController extends ActionController
{
    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @var IdentityToken|null
     */
    protected $identityToken;

    /**
     * @return void
     */
    public function initializeAction()
    {
        parent::initializeAction();

        $account = $this->securityContext->getAccount();
        $identityToken = $account->getCredentialsSource();
        if ($identityToken instanceof IdentityToken) {
            $this->identityToken = $identityToken;
        }
    }
}

````

## Roles from Identity Token

Instead of specifying the Flow authentication roles directly, the
provider can extract the roles from the identity token values. The roles
provided by the token must have the same identifier which is used in
Flow's policy configuration.

Given that the identity token provides a claim called
"https://flownative.com/roles", you may configure the provider as
follows:

```
…
        security:
          authentication:
            providers:
              'Flownative.OpenIdConnect.Client:OidcProvider':
                label: 'OpenID Connect'
                provider: 'Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectProvider'
                providerOptions:
                  rolesFromClaims:
                    - 'https://flownative.com/roles'
                  …
 
```

When a user logs in and her identity token has a value
"https://flownative.com/roles" containing an array of Flow role
identifiers, the OpenID Connect provider will automatically assign these
roles to the transient account.

You may specify multiple claim names which are all considered for
compiling a list of roles.

Check logs for hints if things are not working as expected.

## More about OpenID Connect

See also:

https://openid.net/specs/openid-connect-basic-1_0.html
https://connect2id.com/learn/openid-connect

## Credits and Support

This library was developed by Robert Lemke / Flownative. Feel free to
suggest new features, report bugs or provide bug fixes in our Github
project.

If you'd like us to develop a new feature or need help implementing OIDC
in your project, please
[get in touch with Robert](https://www.flownative.com/robert).
