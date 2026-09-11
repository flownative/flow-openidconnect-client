<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Http;

use Flownative\OpenIdConnect\Client\Authentication\Nonce;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OAuthClient;
use GuzzleHttp\Psr7\Query;
use InvalidArgumentException;
use GuzzleHttp\Psr7\Utils;
use Neos\Flow\Http\CacheControlDirectives;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Context as SecurityContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

final class SetJwtCookieMiddleware implements MiddlewareInterface
{
    public function __construct(
        private array $options,
        private readonly array $authenticationProviderConfiguration,
        private readonly SecurityContext $securityContext,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function initializeObject(): void
    {
        if (isset($this->options['cookieName'])) {
            $this->logger->warning('OpenID Connect: Option "cookieName" was used - please use "cookie.name" instead.', LogEnvironment::fromMethodName(__METHOD__));
            $this->options['cookie']['name'] = $this->options['cookieName'];
        }
        if (isset($this->options['secureCookie'])) {
            $this->logger->warning('OpenID Connect: Option "secureCookie" was used - please use "cookie.secure" instead.', LogEnvironment::fromMethodName(__METHOD__));
            $this->options['cookie']['secure'] = $this->options['secureCookie'];
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        if (!$this->securityContext->isInitialized() && !$this->securityContext->canBeInitialized()) {
            $this->logger->debug('OpenID Connect: Cannot send JWT cookie because the security context could not be initialized.', LogEnvironment::fromMethodName(__METHOD__));
            return $response;
        }

        $cookieSecure = $this->options['cookie']['secure'] ?? true;
        $cookieHttpOnly = $this->options['cookie']['httpOnly'] ?? true;
        $cookieSameSite = $this->options['cookie']['sameSite'] ?? Cookie::SAMESITE_LAX;

        foreach ($this->securityContext->getAuthenticationTokensOfType(OpenIdConnectToken::class) as $token) {
            // Requests with a bearer token don't touch the cookie. Setting it would make the browser send the token automatically, and
            // removing it would end a login based on the cookie because of a failed bearer token.
            if ($token->hasBearerAuthorizationHeader()) {
                continue;
            }
            if ($token->getNonceCookieName() !== '') {
                $response = $response->withAddedHeader('Set-Cookie', (string)Nonce::createRemovalCookie($token->getNonceCookieName(), $cookieSecure));
            }
            $providerName = $token->getAuthenticationProviderName();
            $providerOptions = $this->authenticationProviderConfiguration[$token->getAuthenticationProviderName()]['providerOptions'] ?? [];
            $account = $this->securityContext->getAccountByAuthenticationProviderName($providerName);
            $cookieName = $providerOptions['jwtCookieName'] ?? $this->options['cookie']['name'] ?? 'flownative_oidc_jwt';
            if ($account === null) {
                if (isset($request->getCookieParams()[$cookieName])) {
                    $this->logger->debug(sprintf('OpenID Connect: No account is authenticated using the provider %s, removing JWT cookie "%s".', $providerName, $cookieName), LogEnvironment::fromMethodName(__METHOD__));
                    $response = $this->withoutSharedCaching($this->removeJwtCookie($response, $cookieName, $cookieSecure, $cookieHttpOnly, $cookieSameSite));
                }
                continue;
            }
            try {
                $identityToken = IdentityToken::fromJwt($account->getCredentialsSource());
            } catch (InvalidArgumentException) {
                $this->logger->error(sprintf('OpenID Connect: No identity token found in credentials source of account %s - could not set JWT cookie.', $account->getAccountIdentifier()), LogEnvironment::fromMethodName(__METHOD__));
                continue;
            }

            $response = $this->withoutSharedCaching($this->setJwtCookie($response, $cookieName, $cookieSecure, $cookieHttpOnly, $cookieSameSite, $identityToken->asJwt()));
        }

        // Note: A redirect with a Location header only works if the JWT cookie has a "lax" Same Site configuration. If Same Site of the
        // cookie is set to "strict", apparently only an old-fashioned HTML meta redirect works fine in browsers, which may be error-prone.
        //
        // See also https://bugzilla.mozilla.org/show_bug.cgi?id=1465402
        // and https://web.dev/samesite-cookies-explained/
        if ($cookieSameSite !== Cookie::SAMESITE_STRICT && !$response->hasHeader('Location')) {
            return $this->withRedirectToRemoveOidcQueryParameters($request, $response);
        }

        return $response;
    }

    private function setJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, bool $httpOnly, string $sameSite, string $jwt): ResponseInterface
    {
        $jwtCookie = new Cookie($cookieName, $jwt, 0, null, null, '/', $secure, $httpOnly, $sameSite);
        return $response->withAddedHeader('Set-Cookie', (string)$jwtCookie);
    }

    /**
     * Makes sure that shared caches, like proxies or CDNs, don't store a response which sets or removes the JWT cookie
     */
    private function withoutSharedCaching(ResponseInterface $response): ResponseInterface
    {
        // Note: Flow's StandardsComplianceMiddleware parses the header with the same class, which keeps only one of "public", "private"
        // and "no-cache". A response with "no-cache" therefore gets "no-store" instead of "private".
        $cacheControlDirectives = CacheControlDirectives::fromRawHeader($response->getHeaderLine('Cache-Control'));
        $cacheControlDirectives->removeDirective('s-maxage');
        if ($cacheControlDirectives->getDirective('no-cache') !== null) {
            $cacheControlDirectives->setDirective('no-store');
        } else {
            $cacheControlDirectives->setDirective('private');
        }

        // CDNs which support these headers prefer them over Cache-Control
        return $response
            ->withHeader('Cache-Control', (string)$cacheControlDirectives->getCacheControlHeaderValue())
            ->withoutHeader('CDN-Cache-Control')
            ->withoutHeader('Surrogate-Control');
    }

    private function removeJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, bool $httpOnly, string $sameSite): ResponseInterface
    {
        $emptyJwtCookie = new Cookie($cookieName, '', 1, null, null, '/', $secure, $httpOnly, $sameSite);
        return $response->withAddedHeader('Set-Cookie', (string)$emptyJwtCookie);
    }

    /**
     * Removes any `?flownative_oidc=<...>&flownative_oauth2_authorization_id_oidc=<...>` from the request URL
     * by triggering a redirect to the URL without those query parameters
     */
    private function withRedirectToRemoveOidcQueryParameters(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $queryParameters = Query::parse($request->getUri()->getQuery());
        $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE);
        if (!isset($queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME]) && !isset($queryParameters[$authorizationIdQueryParameterName])) {
            return $response;
        }

        unset($queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME], $queryParameters[$authorizationIdQueryParameterName]);
        $uri = $request->getUri()->withQuery(Query::build($queryParameters));

        return $response
            ->withBody(Utils::streamFor(sprintf('<html><head><meta http-equiv="refresh" content="0;url=%s"/></head></html>', htmlentities((string)$uri, ENT_QUOTES, 'utf-8'))))
            ->withHeader('Location', (string)$uri)
            ->withStatus(303);
    }
}
