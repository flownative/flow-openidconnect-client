<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Http;

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OAuthClient;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Utils;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Component\TrustedProxiesComponent;
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
    /**
     * @var SecurityContext
     */
    private $securityContext;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var array
     */
    private $options;

    /**
     * @var array
     */
    private $authenticationProviderConfiguration;

    public function __construct(array $options, array $authenticationProviderConfiguration, SecurityContext $securityContext, LoggerInterface $logger)
    {
        $this->options = $options;
        $this->authenticationProviderConfiguration = $authenticationProviderConfiguration;
        $this->securityContext = $securityContext;
        $this->logger = $logger;
    }

    /**
     * @return void
     */
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
        if (!isset($this->options['disableTrustedProxiesComponentCompatibility'])) {
            $this->options['disableTrustedProxiesComponentCompatibility'] = false;
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        if (!$this->securityContext->isInitialized() && !$this->securityContext->canBeInitialized()) {
            $this->logger->debug('OpenID Connect: Cannot send JWT cookie because the security context could not be initialized.', LogEnvironment::fromMethodName(__METHOD__));
            return $response;
        }

        $cookieSecure = $this->options['cookie']['secure'] ?? true;
        $cookieHttpOnly = $this->options['cookie']['httpOnly'] ?? false;
        $cookieSameSite = $this->options['cookie']['sameSite'] ?? Cookie::SAMESITE_LAX;

        foreach ($this->securityContext->getAuthenticationTokensOfType(OpenIdConnectToken::class) as $token) {
            $providerName = $token->getAuthenticationProviderName();
            $providerOptions = $this->authenticationProviderConfiguration[$token->getAuthenticationProviderName()]['providerOptions'] ?? [];
            $account = $this->securityContext->getAccountByAuthenticationProviderName($providerName);
            $cookieName = $providerOptions['jwtCookieName'] ?? $this->options['cookie']['name'] ?? 'flownative_oidc_jwt';
            if ($account === null) {
                if (isset($request->getCookieParams()[$cookieName])) {
                    $this->logger->debug(sprintf('OpenID Connect: No account is authenticated using the provider %s, removing JWT cookie "%s".', $providerName, $cookieName), LogEnvironment::fromMethodName(__METHOD__));
                    $response = $this->removeJwtCookie($response, $cookieName, $cookieSecure, $cookieHttpOnly, $cookieSameSite);
                }
                continue;
            }
            $identityToken = $account->getCredentialsSource();
            if (!$identityToken instanceof IdentityToken) {
                $this->logger->error(sprintf('OpenID Connect: No identity token found in credentials source of account %s - could not set JWT cookie.', $account->getAccountIdentifier()), LogEnvironment::fromMethodName(__METHOD__));
                continue;
            }

            $response = $this->setJwtCookie($response, $cookieName, $cookieSecure, $cookieHttpOnly, $cookieSameSite, $identityToken->asJwt());
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

    /**
     * @param ResponseInterface $response
     * @param string $cookieName
     * @param bool $secure
     * @param bool $httpOnly
     * @param string $sameSite
     * @param string $jwt
     * @return ResponseInterface
     */
    private function setJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, bool $httpOnly, string $sameSite, string $jwt): ResponseInterface
    {
        $jwtCookie = new Cookie($cookieName, $jwt, 0, null, null, '/', $secure, $httpOnly, $sameSite);
        return $response->withAddedHeader('Set-Cookie', (string)$jwtCookie);
    }

    /**
     * @param ResponseInterface $response
     * @param string $cookieName
     * @param bool $secure
     * @param bool $httpOnly
     * @param string $sameSite
     * @return ResponseInterface
     */
    private function removeJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, bool $httpOnly, string $sameSite): ResponseInterface
    {
        $emptyJwtCookie = new Cookie($cookieName, '', 1, null, null, '/', $secure, $httpOnly, $sameSite);
        return $response->withAddedHeader('Set-Cookie', (string)$emptyJwtCookie);
    }

    /**
     * Removes any `?flownative_oidc=<...>&flownative_oauth2_authorization_id_oidc=<...>` from the request URL
     * by triggering a redirect to the URL without those query parameters
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    private function withRedirectToRemoveOidcQueryParameters(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        // Provide backwards-compatibility with Flow 6.3 and earlier, where the Trusted Proxies Middleware did not exist yet:
        if (class_exists(TrustedProxiesComponent::class) && class_exists(ComponentContext::class) && $this->options['disableTrustedProxiesComponentCompatibility'] === false) {
            $componentContext = new ComponentContext($request, $response);
            $trustedProxiesComponent = new TrustedProxiesComponent();
            $trustedProxiesComponent->handle($componentContext);
            $request = $componentContext->getHttpRequest();
        }

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
