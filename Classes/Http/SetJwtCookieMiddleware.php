<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Http;

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OAuthClient;
use GuzzleHttp\Psr7\Query;
use Neos\Flow\Annotations as Flow;
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
     * @Flow\Inject
     * @var SecurityContext
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var array
     */
    private $options;

    /**
     * @var array
     */
    private $authenticationProviderConfiguration;

    public function __construct(array $options, array $authenticationProviderConfiguration)
    {
        $this->options = $options;
        $this->authenticationProviderConfiguration = $authenticationProviderConfiguration;
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
        foreach ($this->securityContext->getAuthenticationTokensOfType(OpenIdConnectToken::class) as $token) {
            $providerName = $token->getAuthenticationProviderName();
            $providerOptions = $this->authenticationProviderConfiguration[$token->getAuthenticationProviderName()]['providerOptions'] ?? [];
            $account = $this->securityContext->getAccountByAuthenticationProviderName($providerName);
            $cookieName = $providerOptions['jwtCookieName'] ?? $this->options['cookie']['name'] ?? 'flownative_oidc_jwt';
            $cookieSecure = $this->options['cookie']['secure'] ?? true;
            $cookieSameSite = $this->options['cookie']['sameSite'] ?? 'strict';
            if ($account === null) {
                if (isset($request->getCookieParams()[$cookieName])) {
                    $this->logger->debug(sprintf('OpenID Connect: No account is authenticated using the provider %s, removing JWT cookie "%s".', $providerName, $cookieName), LogEnvironment::fromMethodName(__METHOD__));
                    $response = $this->removeJwtCookie($response, $cookieName, $cookieSecure, $cookieSameSite);
                }
                continue;
            }
            $identityToken = $account->getCredentialsSource();
            if (!$identityToken instanceof IdentityToken) {
                $this->logger->error(sprintf('OpenID Connect: No identity token found in credentials source of account %s - could not set JWT cookie.', $account->getAccountIdentifier()), LogEnvironment::fromMethodName(__METHOD__));
                continue;
            }

            $response = $this->setJwtCookie($response, $cookieName, $cookieSecure, $cookieSameSite, $identityToken->asJwt());
        }

        return $this->removeOidcQueryParameters($request, $response);
    }

    /**
     * @param ResponseInterface $response
     * @param string $cookieName
     * @param bool $secure
     * @param string $sameSite
     * @param string $jwt
     * @return ResponseInterface
     */
    private function setJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, string $sameSite, string $jwt): ResponseInterface
    {
        $jwtCookie = new Cookie($cookieName, $jwt, 0, null, null, '/', $secure, false, $sameSite);
        return $response->withAddedHeader('Set-Cookie', (string)$jwtCookie);
    }

    /**
     * @param ResponseInterface $response
     * @param string $cookieName
     * @param bool $secure
     * @param string $sameSite
     * @return ResponseInterface
     */
    private function removeJwtCookie(ResponseInterface $response, string $cookieName, bool $secure, string $sameSite): ResponseInterface
    {
        $emptyJwtCookie = new Cookie($cookieName, '', 1, null, null, '/', $secure, false, $sameSite);
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
    private function removeOidcQueryParameters(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        if ($response->hasHeader('Location')) {
            return $response;
        }
        $queryParameters = Query::parse($request->getUri()->getQuery());
        $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE);
        if (!isset($queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME]) && !isset($queryParameters[$authorizationIdQueryParameterName])) {
            return $response;
        }
        unset($queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME], $queryParameters[$authorizationIdQueryParameterName]);
        return $response->withHeader('Location', (string)$request->getUri()->withQuery(Query::build($queryParameters)));
    }
}
