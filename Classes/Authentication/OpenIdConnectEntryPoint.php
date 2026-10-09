<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OpenIdConnect\Client\ConfigurationException;
use Flownative\OpenIdConnect\Client\CookieSettings;
use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClientFactory;
use Flownative\OpenIdConnect\Client\ServiceException;
use GuzzleHttp\Psr7\Query;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\ContentStream;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Authentication\EntryPoint\AbstractEntryPoint;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

final class OpenIdConnectEntryPoint extends AbstractEntryPoint
{
    private const int MAXIMUM_PENDING_LOGINS = 5;

    /**
     * Not lazy, because a named injection would otherwise receive a dependency proxy which does not match the type.
     */
    #[Flow\Inject(name: 'Neos.Flow:SecurityLogger', lazy: false)]
    protected ?LoggerInterface $logger = null;

    #[Flow\Inject]
    protected OpenIdConnectClientFactory $openIdConnectClientFactory;

    #[Flow\InjectConfiguration(path: 'middleware')]
    protected array $middlewareSettings = [];

    /**
     * @throws ConfigurationException
     */
    public function startAuthentication(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $this->validateOptions();
        $this->logger?->debug(sprintf('OpenID Connect: OpenIdConnectEntryPoint starting authentication for service "%s" ...', $this->options['serviceName']), LogEnvironment::fromMethodName(__METHOD__));

        if (!$this->isNavigation($request)) {
            $this->logger?->debug('OpenID Connect: OpenIdConnectEntryPoint answers with status 401, because the request does not come from a browser which navigates to a page', LogEnvironment::fromMethodName(__METHOD__));
            return $response
                ->withStatus(401)
                ->withHeader('WWW-Authenticate', 'Bearer')
                ->withHeader('Cache-Control', 'no-store');
        }

        // The identity provider usually sends the user back without asking, so the new login would be rejected again, in an endless loop
        if ($this->isReturnFromIdentityProvider($request)) {
            $this->logger?->notice(sprintf('OpenID Connect: The login for service "%s" was rejected when the browser returned from the identity provider, showing an error instead of starting another login', $this->options['serviceName']), LogEnvironment::fromMethodName(__METHOD__));
            return $this->createLoginFailedResponse($request, $response);
        }

        $nonce = Nonce::generate();
        $client = $this->openIdConnectClientFactory->create($this->options['serviceName']);
        try {
            $providerUri = $client->startAuthorization($request->getUri(), $this->options['scope'] ?? '', $nonce, $this->options['requestRefreshToken'] ?? true, $this->options['authorizationParameters'] ?? []);
        } catch (OAuthClientException | ServiceException $exception) {
            $this->logger?->error(sprintf('OpenID Connect: Authentication for service "%s" failed: %s', $this->options['serviceName'], $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return $response;
        }

        // The query contains the state and the nonce of the login
        $this->logger?->info(sprintf('OpenID Connect: OpenIdConnectEntryPoint for service "%s" redirecting to %s', $this->options['serviceName'], $providerUri->withQuery('')), LogEnvironment::fromMethodName(__METHOD__));

        $body = ContentStream::fromContents(sprintf('<html lang="en"><head><meta http-equiv="refresh" content="0;url=%s"/><title>OpenID Connect</title></head></html>', htmlentities((string)$providerUri, ENT_QUOTES, 'utf-8')));
        // The response carries the secret of the nonce, so no cache may store it
        $response = $response
            ->withBody($body)
            ->withStatus(303)
            ->withHeader('Location', (string)$providerUri)
            ->withHeader('Cache-Control', 'no-store');

        $cookieSettings = CookieSettings::fromMiddlewareSettings($this->middlewareSettings);

        // Each login in progress keeps a cookie until it expires. Without a limit, many logins which were started but never finished
        // would soon exceed the size of request headers which web servers accept.
        $pendingNonceCookieNames = Nonce::findCookieNames($request->getCookieParams(), $cookieSettings);
        if (count($pendingNonceCookieNames) >= self::MAXIMUM_PENDING_LOGINS) {
            foreach ($pendingNonceCookieNames as $cookieName) {
                $response = $response->withAddedHeader('Set-Cookie', (string)Nonce::createRemovalCookie($cookieName, $cookieSettings));
            }
        }
        return $response->withAddedHeader('Set-Cookie', (string)$nonce->createCookie($cookieSettings));
    }

    /**
     * @throws ConfigurationException
     */
    private function validateOptions(): void
    {
        if (!isset($this->options['serviceName'])) {
            throw new ConfigurationException('OpenID Connect: "serviceName" option was not configured for OpenIdConnectEntryPoint', 1559898606);
        }
        if (isset($this->options['scope']) && !is_string($this->options['scope'])) {
            throw new ConfigurationException('OpenID Connect: "scope" option was not configured correctly for OpenIdConnectEntryPoint', 1560259102);
        }
        if (isset($this->options['requestRefreshToken']) && !is_bool($this->options['requestRefreshToken'])) {
            throw new ConfigurationException('OpenID Connect: "requestRefreshToken" option must be a boolean for OpenIdConnectEntryPoint', 1789108753);
        }
        $authorizationParameters = $this->options['authorizationParameters'] ?? [];
        if (!is_array($authorizationParameters) || array_filter($authorizationParameters, static fn (mixed $value, mixed $name): bool => !is_string($name) || $name === '' || !is_string($value), ARRAY_FILTER_USE_BOTH) !== []) {
            throw new ConfigurationException('OpenID Connect: "authorizationParameters" option must map parameter names to strings for OpenIdConnectEntryPoint', 1791540884);
        }
        $loginFailedRedirectUri = $this->options['loginFailedRedirectUri'] ?? null;
        if ($loginFailedRedirectUri !== null && !self::isRedirectTarget($loginFailedRedirectUri)) {
            throw new ConfigurationException('OpenID Connect: "loginFailedRedirectUri" option must be a path starting with "/" or an absolute http(s) URI for OpenIdConnectEntryPoint', 1791540885);
        }
    }

    /**
     * Tells if a browser navigates to a page with this request. Only then it can follow the redirect to the identity provider and come
     * back with the login. Scripts and API clients would receive a redirect which they can't use.
     */
    private function isNavigation(ServerRequestInterface $request): bool
    {
        // Only a bearer token counts, because browsers also send "Basic" credentials, for example for a staging site behind a password
        if (stripos($request->getHeaderLine('Authorization'), 'Bearer ') === 0 || $request->getHeaderLine('X-Requested-With') === 'XMLHttpRequest') {
            return false;
        }
        // Browsers which don't send this header are expected to navigate
        $fetchMode = $request->getHeaderLine('Sec-Fetch-Mode');
        return $fetchMode === '' || $fetchMode === 'navigate';
    }

    private function isReturnFromIdentityProvider(ServerRequestInterface $request): bool
    {
        return array_key_exists(OpenIdConnectToken::OIDC_PARAMETER_NAME, Query::parse($request->getUri()->getQuery()));
    }

    /**
     * A path of this site or an absolute address, but no path starting with "//" or "/\", which browsers read as an address of another host
     *
     * Browsers also drop tabs and line breaks before they read an address, so whitespace and control characters are not accepted at all.
     */
    private static function isRedirectTarget(mixed $uri): bool
    {
        if (!is_string($uri) || preg_match('/[\x00-\x20\x7f]/', $uri) === 1) {
            return false;
        }
        if (str_starts_with($uri, '/')) {
            return !str_starts_with($uri, '//') && !str_starts_with($uri, '/\\');
        }
        return in_array(parse_url($uri, PHP_URL_SCHEME), ['https', 'http'], true) && is_string(parse_url($uri, PHP_URL_HOST));
    }

    /**
     * Sends the browser to the page of the application configured for a failed login, or shows a page of its own with a link to try
     * again, which leads to the same page without the parameters of the rejected login
     *
     * The configured page must be reachable without a login, or this entry point starts the rejected login again, in an endless loop.
     */
    private function createLoginFailedResponse(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $loginFailedRedirectUri = $this->options['loginFailedRedirectUri'] ?? null;
        if (is_string($loginFailedRedirectUri)) {
            return $response
                ->withStatus(303)
                ->withHeader('Location', $loginFailedRedirectUri)
                ->withHeader('Cache-Control', 'no-store');
        }

        $queryParameters = Query::parse($request->getUri()->getQuery());
        unset(
            $queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME],
            $queryParameters[OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE)],
            $queryParameters[OAuthClient::generateAuthorizationErrorQueryParameterName(OAuthClient::SERVICE_TYPE)]
        );
        $retryUri = (string)$request->getUri()->withQuery(Query::build($queryParameters));

        $body = sprintf('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Login failed</title></head><body><h1>Login failed</h1><p>The login could not be completed. <a href="%s">Try again</a></p></body></html>', htmlentities($retryUri, ENT_QUOTES, 'utf-8'));
        return $response
            ->withStatus(403)
            ->withBody(ContentStream::fromContents($body))
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store');
    }
}
