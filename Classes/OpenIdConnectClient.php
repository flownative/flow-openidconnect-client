<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

use Doctrine\ORM\Exception\ORMException;
use Doctrine\ORM\OptimisticLockException;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OpenIdConnect\Client\Authentication\Nonce;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Authentication\TokenArguments;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Query;
use InvalidArgumentException;
use JsonException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Neos\Cache\Exception as CacheException;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Utility\Arrays;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;
use SodiumException;

final class OpenIdConnectClient
{
    private const array DEFAULT_OPTIONS = [
        'issuer' => '',
        'clientId' => '',
        'clientSecret' => '',
        'authorizationEndpoint' => '',
        'tokenEndpoint' => '',
        'userInfoEndpoint' => '',
        'jwksUri' => '',
        'scopesSupported' => ''
    ];

    private const array DISCOVERY_OPTIONS_MAPPING = [
        'issuer' => 'issuer',
        'authorization_endpoint' => 'authorizationEndpoint',
        'token_endpoint' => 'tokenEndpoint',
        'userinfo_endpoint' => 'userInfoEndpoint',
        'jwks_uri' => 'jwksUri',
        'scopes_supported' => 'scopesSupported'
    ];

    /**
     * Service name which identifies the configuration of this OpenID Connect Client instance
     */
    private const int ACCESS_TOKEN_RENEWAL_MARGIN = 30; # seconds before expiration

    private string $serviceName;

    private array $options = [];

    private OAuthClient $oAuthClient;

    #[Flow\InjectConfiguration]
    protected array $settings;

    protected HttpClient $httpClient;

    /**
     * Not lazy, because a named injection would otherwise receive a dependency proxy which does not match the type.
     */
    #[Flow\Inject(name: 'Neos.Flow:SecurityLogger', lazy: false)]
    protected ?LoggerInterface $logger = null;

    #[Flow\Inject]
    protected HashService $hashService;

    /**
     * Not typed, because Flow injects the caches configured in Objects.yaml lazily and the dependency proxy would not match the type.
     *
     * @var VariableFrontend
     */
    protected $discoveryCache;

    /**
     * @var VariableFrontend
     */
    protected $jwksCache;

    public function __construct(string $serviceName)
    {
        $this->serviceName = $serviceName;
        $this->httpClient = new HttpClient();
    }

    /**
     * Prepare options and run auto-discovery, if configured
     *
     * @throws ConnectionException
     * @throws ConfigurationException
     * @throws CacheException
     */
    public function initializeObject(): void
    {
        if (!isset($this->settings['services'][$this->serviceName])) {
            throw new ConfigurationException(sprintf('OpenID Connect Client: No configuration found for service "%s".', $this->serviceName), 1554914085);
        }
        if (!isset($this->settings['services'][$this->serviceName]['options'])) {
            throw new ConfigurationException(sprintf('OpenID Connect Client: Missing options in configuration for service "%s".', $this->serviceName), 1554914112);
        }
        if (!is_array($this->settings['services'][$this->serviceName]['options'])) {
            throw new ConfigurationException(sprintf('OpenID Connect Client: Invalid configuration for service "%s", options must be an array.', $this->serviceName), 1554914157);
        }
        $this->options = Arrays::arrayMergeRecursiveOverrule(self::DEFAULT_OPTIONS, $this->settings['services'][$this->serviceName]['options']);
        if (isset($this->options['discoveryUri'])) {
            $this->amendOptionsWithDiscovery($this->options['discoveryUri']);
        }
        if (empty($this->options['jwksUri'])) {
            throw new ConfigurationException(sprintf('OpenID Connect Client: Option "discoveryUri" or "jwksUri" has to be configured for service "%s".', $this->serviceName), 1554968498);
        }

        $this->oAuthClient = new OAuthClient($this->serviceName);
        $this->oAuthClient->setOpenIdConnectClient($this);
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Returns an OAuth access token of the Client Credentials Flow for machine-to-machine applications
     *
     * This method will check if an access token already exists (stored in an Authorization record), and
     * requests one via OAuth if it doesn't or if it expires soon. The authorization id which leads to the
     * Authorization record is deterministic and derived from the service name, client id, scope and
     * additional parameters.
     *
     * @param string $serviceName The service name used in the OAuth configuration
     * @param string $scope The authorization scope. Must be identifiers separated by space. With an empty scope, the identity provider uses its default scope
     * @param array $additionalParameters Additional parameters to provide in the request body while requesting the token. For example ['audience' => 'https://www.example.com/api/v1']
     * @throws AuthenticationException
     * @throws ConnectionException
     * @throws IdentityProviderException
     * @throws GuzzleException
     * @throws SodiumException
     */
    public function getAccessToken(string $serviceName, string $clientId, string $clientSecret, string $scope, array $additionalParameters = []): AccessToken
    {
        $accessToken = null;
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant($serviceName, $clientId, $scope, $additionalParameters);
        $authorization = $this->getAuthorization($authorizationId);

        if ($authorization !== null) {
            $accessToken = $authorization->getAccessToken();
            if ($accessToken === null) {
                $this->logger?->warning(sprintf('OpenID Connect Client: Authorization %s for service "%s", clientId "%s" contained no token', $authorizationId, $serviceName, $clientId), LogEnvironment::fromMethodName(__METHOD__));
            } elseif ($this->expiresSoon($authorization, $accessToken)) {
                $this->logger?->info(sprintf('OpenID Connect Client: Access token contained in authorization %s for service "%s", clientId "%s" has expired or expires soon', $authorizationId, $serviceName, $clientId), LogEnvironment::fromMethodName(__METHOD__));
            }
        }

        if ($authorization === null || $accessToken === null || $this->expiresSoon($authorization, $accessToken)) {
            $this->logger?->info(sprintf('OpenID Connect Client: Requesting new access token for service %s using client id %s %s', $serviceName, $clientId, ($scope ? 'requesting scope "' . $scope . '"' : 'requesting no scope')), LogEnvironment::fromMethodName(__METHOD__));

            $this->oAuthClient->requestAccessToken($serviceName, $clientId, $clientSecret, $scope, $additionalParameters);
            $authorization = $this->getAuthorization($authorizationId);
            if ($authorization === null) {
                throw new ConnectionException(sprintf('OpenID Connect Client: Failed retrieving access token for service "%s", clientId "%s": No authorization found for id %s', $serviceName, $clientId, $authorizationId));
            }

            $accessToken = $authorization->getAccessToken();
            if ($accessToken === null) {
                throw new AuthenticationException(sprintf('OpenID Connect Client: Failed retrieving access token for service "%s", clientId "%s": Authorization %s contains no token', $serviceName, $clientId, $authorizationId));
            }
        } else {
            $this->logger?->debug(sprintf('OpenID Connect Client: Using existing access token for service %s using client id %s %s', $serviceName, $clientId, ($scope ? 'with scope "' . $scope . '"' : 'without a scope')), LogEnvironment::fromMethodName(__METHOD__));
        }

        return $accessToken;
    }

    /**
     * Start authorization via OAuth, with the Authorization Code Flow, using an OpenID Connect scope
     *
     * This method is an interactive authorization, which usually requires a browser to work. The response which redirects the browser
     * must also set the cookie of the given nonce, otherwise the login is rejected when the browser returns.
     *
     * @param string $scope The authorization scope. Must be identifiers separated by space. "openid" will automatically be requested
     * @param bool $requestRefreshToken If "offline_access" should be requested, so that an expired identity token can be refreshed
     * @throws OAuthClientException
     */
    public function startAuthorization(UriInterface $returnToUri, string $scope, Nonce $nonce, bool $requestRefreshToken = true): UriInterface
    {
        $returnArguments = (string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => $this->serviceName, TokenArguments::NONCE => $nonce->value], $this->hashService);
        if (str_starts_with($returnArguments, 'ERROR')) {
            throw new RuntimeException(substr($returnArguments, 6));
        }

        // After a rejected return, the URI still contains the parameters of that login, which must not be passed on again
        $queryParameters = Query::parse($returnToUri->getQuery());
        unset($queryParameters[OAuthClient::generateAuthorizationIdQueryParameterName(OAuthClient::SERVICE_TYPE)]);
        $queryParameters[OpenIdConnectToken::OIDC_PARAMETER_NAME] = $returnArguments;
        $returnToUri = $returnToUri->withQuery(Query::build($queryParameters));

        if (empty($this->options['clientId']) || empty($this->options['clientSecret'])) {
            throw new RuntimeException(sprintf('OpenID Connect Client: Authorization Code Flow requires "clientId" and "clientSecret" to be configured for service "%s".', $this->serviceName), 1596456168);
        }
        return $this->oAuthClient->startAuthorization($this->options['clientId'], $this->options['clientSecret'], $returnToUri, $this->buildAuthorizationScope($scope, $requestRefreshToken), ['nonce' => $nonce->value]);
    }

    /**
     * Returns the current identity token and refresh token in a TokenSet
     *
     * @throws ConnectionException
     * @throws ServiceException|SodiumException
     */
    public function getIdentityToken(string $authorizationIdentifier): TokenSet
    {
        $authorization = $this->getAuthorization($authorizationIdentifier);
        if (!$authorization instanceof Authorization) {
            throw new ServiceException(sprintf('OpenID Connect Client: Authorization %s was not found', $authorizationIdentifier), 1567853403);
        }
        $accessToken = $authorization->getAccessToken();
        if (!$accessToken) {
            throw new ServiceException(sprintf('OpenID Connect Client: Authorization %s contained no access token', $authorizationIdentifier), 1567853441);
        }
        $tokenValues = $accessToken->getValues();
        if (!isset($tokenValues['id_token'])) {
            throw new ServiceException('OpenID Connect Client: No id_token found in values of current oAuth token', 1559208674);
        }
        try {
            return new TokenSet(
                IdentityToken::fromJwt($tokenValues['id_token']),
                $accessToken->getRefreshToken()
            );
        } catch (InvalidArgumentException $e) {
            throw new ServiceException('OpenID Connect Client: Failed parsing identity token from JWT', 1602501992, $e);
        }
    }

    /**
     * Removes the specified authorization, so that it can't be used again
     */
    public function removeAuthorization(string $authorizationIdentifier): void
    {
        $this->oAuthClient->removeAuthorization($authorizationIdentifier);
    }

    /**
     * Retrieves the JSON Web Key Set from the endpoint configured via the "jwksUri" option
     *
     * @throws CacheException
     * @throws ConnectionException
     * @throws ServiceException
     * @see https://tools.ietf.org/html/rfc7517
     */
    public function getJwks(): array
    {
        $cacheIdentifier = sha1($this->options['jwksUri']);
        $jwks = $this->jwksCache->get($cacheIdentifier);
        if (empty($jwks)) {
            try {
                $response = $this->httpClient->request('GET', $this->options['jwksUri']);
            } catch (GuzzleException $e) {
                throw new ConnectionException(sprintf('OpenID Connect Client: Failed retrieving JWKS from %s: %s', $this->options['jwksUri'], $e->getMessage()), 1559211266);
            }

            try {
                $response = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException $e) {
                throw new ServiceException(sprintf('OpenID Connect Client: Failed decoding response while retrieving JWKS from %s', $this->options['jwksUri']), 1739990452, $e);
            }
            if (!is_array($response) || !isset($response['keys'])) {
                throw new ServiceException(sprintf('OpenID Connect Client: Invalid response data while retrieving JWKS from %s', $this->options['jwksUri']), 1559211340);
            }
            $jwks = $response['keys'];
            $this->jwksCache->set($cacheIdentifier, $jwks);
        }
        return $jwks;
    }

    /**
     * @throws ServiceException
     * @throws ConnectionException
     */
    public function refreshIdentityToken(string $refreshToken): TokenSet
    {
        $tokenEndpoint = $this->options['tokenEndpoint'];
        try {
            $response = $this->httpClient->request('POST', $tokenEndpoint, [
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'client_id' => $this->settings['services'][$this->serviceName]['options']['clientId'],
                    'client_secret' => $this->settings['services'][$this->serviceName]['options']['clientSecret'],
                    'refresh_token' => $refreshToken,
                ]
            ]);
        } catch (GuzzleException $e) {
            throw new ConnectionException(sprintf('OpenID Connect Client: Failed refreshing identity token from %s: %s', $tokenEndpoint, $e->getMessage()), 1741193078);
        }

        try {
            $response = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new ServiceException(sprintf('OpenID Connect Client: Failed decoding response while refreshing identity token from %s', $tokenEndpoint), 1741193238, $e);
        }
        if (!is_array($response) || !is_string($response['id_token'] ?? null)) {
            throw new ServiceException(sprintf('OpenID Connect Client: Invalid response data while refreshing identity token from %s', $tokenEndpoint), 1741193241);
        }

        try {
            // Identity providers which rotate refresh tokens return a new one, and the previous one becomes invalid
            $refreshToken = $response['refresh_token'] ?? '';
            $result = new TokenSet(IdentityToken::fromJwt($response['id_token']), is_string($refreshToken) ? $refreshToken : '');
        } catch (InvalidArgumentException $e) {
            throw new ServiceException(sprintf('OpenID Connect Client: Could not construct identity token from response data while refreshing identity token from %s', $tokenEndpoint), 1741271679, $e);
        }

        return $result;
    }

    /**
     * @throws ConnectionException
     * @throws CacheException
     */
    private function amendOptionsWithDiscovery(string $discoveryUri): void
    {
        $cacheIdentifier = md5('options:' . $discoveryUri);
        $discoveredOptions = $this->discoveryCache->get($cacheIdentifier);
        if (empty($discoveredOptions)) {
            try {
                $response = $this->httpClient->request('GET', $discoveryUri);
            } catch (GuzzleException $e) {
                throw new ConnectionException(sprintf('OpenID Connect Client: Failed discovering options at %s: %s', $discoveryUri, $e->getMessage()), 1554902567);
            }
            try {
                $discoveredOptions = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                $discoveredOptions = null;
            }
            if (!is_array($discoveredOptions)) {
                throw new ConnectionException('OpenID Connect Client: Discovery endpoint returned invalid response.', 1554903349);
            }
            $this->discoveryCache->set($cacheIdentifier, $discoveredOptions);
            $this->logger?->info(sprintf('OpenID Connect Client: Auto-discovery via %s succeeded and stored into cache.', $discoveryUri), LogEnvironment::fromMethodName(__METHOD__));
        }

        foreach ($discoveredOptions as $optionName => $optionValue) {
            if (isset(self::DISCOVERY_OPTIONS_MAPPING[$optionName])) {
                $this->options[self::DISCOVERY_OPTIONS_MAPPING[$optionName]] = $optionValue;
            }
        }
    }

    /**
     * Returns the specified authorization
     *
     * @throws ConnectionException
     */
    /**
     * A token which is renewed shortly before its expiration can't expire while a request uses it
     */
    private function expiresSoon(Authorization $authorization, AccessToken $accessToken): bool
    {
        // A token without an expiration time expires with its authorization, after the default token lifetime of the OAuth client
        $expirationTimestamp = $accessToken->getExpires() ?? $authorization->getExpires()?->getTimestamp();
        return $expirationTimestamp !== null && $expirationTimestamp <= time() + self::ACCESS_TOKEN_RENEWAL_MARGIN;
    }

    private function getAuthorization(string $authorizationIdentifier): ?Authorization
    {
        try {
            $authorization = $this->oAuthClient->getAuthorization($authorizationIdentifier);
        } catch (ORMException|OptimisticLockException $exception) {
            throw new ConnectionException(sprintf('OpenID Connect Client: Failed retrieving oAuth token %s: %s', $authorizationIdentifier, $exception->getMessage()), 1559202394);
        }
        return $authorization;
    }

    private function buildAuthorizationScope(string $scope, bool $requestRefreshToken): string
    {
        $requiredScopeIdentifiers = $requestRefreshToken ? ['openid', 'offline_access'] : ['openid'];
        return trim(implode(' ', array_unique(array_merge(explode(' ', $scope), $requiredScopeIdentifiers))));
    }
}
