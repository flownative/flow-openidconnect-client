<?php

namespace Flownative\OpenIdConnect\Client;

use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectToken;
use Flownative\OpenIdConnect\Client\Authentication\TokenArguments;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Neos\Cache\Exception as CacheException;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Utility\Arrays;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;

final class OpenIdConnectClient
{
    /**
     * Service name which identifies the configuration of this OpenID Connect Client instance
     *
     * @var string
     */
    private $serviceName;

    /**
     * Options set for this client
     *
     * @var array
     */
    private $options;

    /**
     * Instance of the OAuth Client used for authorization
     *
     * @var OAuthClient
     */
    private $oAuthClient;

    /**
     * @Flow\InjectConfiguration
     * @var array
     */
    protected $settings;

    /**
     * @var HttpClient
     */
    protected $httpClient;

    /**
     * @Flow\Inject(name="Neos.Flow:SecurityLogger")
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var VariableFrontend
     */
    protected $discoveryCache;

    /**
     * @var VariableFrontend
     */
    protected $jwksCache;

    /**
     * @const array
     */
    private const DEFAULT_OPTIONS = [
        'issuer' => '',
        'clientId' => '',
        'clientSecret' => '',
        'authorizationEndpoint' => '',
        'tokenEndpoint' => '',
        'userInfoEndpoint' => '',
        'jwksUri' => '',
        'scopesSupported' => ''
    ];

    /**
     * @const array
     */
    private const DISCOVERY_OPTIONS_MAPPING = [
        'issuer' => 'issuer',
        'authorization_endpoint' => 'authorizationEndpoint',
        'token_endpoint' => 'tokenEndpoint',
        'userinfo_endpoint' => 'userInfoEndpoint',
        'jwks_uri' => 'jwksUri',
        'scopes_supported' => 'scopesSupported'
    ];

    /**
     * @param string $serviceName
     */
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

    /**
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Returns OAuth access token, using an OpenID Connect scope
     *
     * This method is used using the OAuth Client Credentials Flow for machine-to-machine applications.
     * Therefore the grant type must be Authorization::GRANT_CLIENT_CREDENTIALS. You need to specify the
     * client identifier and client secret and may optionally specify a scope.
     *
     * This method will check if an access token already exists (stored in an Authorization record), and
     * if it doesn't, requests one via OAuth. The authorization id which leads to the Authorization record
     * is deterministic and derived from the service name, client id, client secret and scope.
     *
     * @param string $serviceName The service name used in the OAuth configuration
     * @param string $clientId Client ID
     * @param string $clientSecret Client Secret
     * @param string $scope The authorization scope. Must be identifiers separated by space. "openid" will automatically be requested
     * @param array $additionalParameters Additional parameters to provide in the request body while requesting the token. For example ['audience' => 'https://www.example.com/api/v1']
     * @return AccessToken
     * @throws AuthenticationException
     * @throws ConnectionException
     * @throws IdentityProviderException
     */
    public function getAccessToken(string $serviceName, string $clientId, string $clientSecret, string $scope, array $additionalParameters = []): AccessToken
    {
        $scope = trim(implode(' ', array_unique(array_merge(explode(' ', $scope), ['openid']))));

        $accessToken = null;
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant($serviceName, $clientId, $clientSecret, $scope, $additionalParameters);
        $authorization = $this->getAuthorization($authorizationId);

        if ($authorization !== null) {
            $accessToken = $authorization->getAccessToken();
            if ($accessToken === null) {
                $this->logger->warning(sprintf('OpenID Connect Client: Authorization %s for service "%s", clientId "%s" contained no token', $authorizationId, $serviceName, $clientId), LogEnvironment::fromMethodName(__METHOD__));
            } elseif ($accessToken->hasExpired()) {
                $this->logger->info(sprintf('OpenID Connect Client: Access token contained in authorization %s for service "%s", clientId "%s" has expired', $authorizationId, $serviceName, $clientId), LogEnvironment::fromMethodName(__METHOD__));
            }
        }

        if ($accessToken === null || $accessToken->hasExpired()) {
            $this->logger->info(sprintf('OpenID Connect Client: Requesting new access token for service %s using client id %s %s', $serviceName, $clientId, ($scope ? 'requesting scope "' . $scope . '"' : 'requesting no scope')), LogEnvironment::fromMethodName(__METHOD__));

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
            $expiresInSeconds = $accessToken->getExpires() - time();
            $this->logger->info(sprintf('OpenID Connect Client: Using existing access token for service %s using client id %s %s. Remaining lifetime: %d seconds', $serviceName, $clientId, ($scope ? 'with scope "' . $scope . '"' : 'without a scope'), $expiresInSeconds), LogEnvironment::fromMethodName(__METHOD__));
        }

        return $accessToken;
    }

    /**
     * Start authorization via OAuth, with the Authorization Code Flow, using an OpenID Connect scope
     *
     * This method is an interactive authorization, which usually requires a browser to work.
     *
     * @param UriInterface $returnToUri The desired return URI
     * @param string $scope The authorization scope. Must be identifiers separated by space. "openid" will automatically be requested
     * @return UriInterface The rendered URI to redirect to
     * @throws OAuthClientException
     */
    public function startAuthorization(UriInterface $returnToUri, string $scope): UriInterface
    {
        $returnArguments = (string)TokenArguments::fromArray([TokenArguments::SERVICE_NAME => $this->serviceName]);
        if (str_starts_with($returnArguments, 'ERROR')) {
            throw new \RuntimeException(substr($returnArguments, 6));
        }
        $returnToUri = $returnToUri->withQuery(trim($returnToUri->getQuery() . '&' . OpenIdConnectToken::OIDC_PARAMETER_NAME . '=' . urlencode($returnArguments), '&'));
        $scope = trim(implode(' ', array_unique(array_merge(explode(' ', $scope), ['openid']))));

        if (empty($this->options['clientId']) || empty($this->options['clientSecret'])) {
            throw new \RuntimeException(sprintf('OpenID Connect Client: Authorization Code Flow requires "clientId" and "clientSecret" to be configured for service "%s".', $this->serviceName), 1596456168);
        }
        return $this->oAuthClient->startAuthorization($this->options['clientId'], $this->options['clientSecret'], $returnToUri, $scope);
    }

    /**
     * Returns the current OpenId Connect Identity Token
     *
     * @param string $authorizationIdentifier
     * @return IdentityToken
     * @throws ConnectionException
     * @throws ServiceException
     */
    public function getIdentityToken(string $authorizationIdentifier): IdentityToken
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
            return IdentityToken::fromJwt($tokenValues['id_token']);
        } catch (\JsonException $e) {
            throw new ServiceException('OpenID Connect Client: Failed parsing identity token from JWT', 1602501992, $e);
        }
    }

    /**
     * Removes the specified authorization, so that it can't be used again
     *
     * @param string $authorizationIdentifier
     * @return void
     */
    public function removeAuthorization(string $authorizationIdentifier): void
    {
        $this->oAuthClient->removeAuthorization($authorizationIdentifier);
    }

    /**
     * Retrieves the JSON Web Key Set from the endpoint configured via the "jwksUri" option
     *
     * @return array
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

            $response = json_decode($response->getBody()->getContents(), true);
            if (!is_array($response) || !isset($response['keys'])) {
                throw new ServiceException(sprintf('OpenID Connect Client: Failed decoding response while retrieving JWKS from %s', $this->options['jwksUri']), 1559211340);
            }
            $jwks = $response['keys'];
            $this->jwksCache->set($cacheIdentifier, $jwks);
        }
        return $jwks;
    }

    /**
     * @param string $discoveryUri
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
            $discoveredOptions = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
            if (!is_array($discoveredOptions)) {
                throw new ConnectionException('OpenID Connect Client: Discovery endpoint returned invalid response.', 1554903349);
            }
            $this->discoveryCache->set($cacheIdentifier, $discoveredOptions);
            $this->logger->info(sprintf('OpenID Connect Client: Auto-discovery via %s succeeded and stored into cache.', $discoveryUri), LogEnvironment::fromMethodName(__METHOD__));
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
     * @param string $authorizationIdentifier
     * @return Authorization|null
     * @throws ConnectionException
     */
    private function getAuthorization(string $authorizationIdentifier): ?Authorization
    {
        try {
            $authorization = $this->oAuthClient->getAuthorization($authorizationIdentifier);
        } catch (ORMException | OptimisticLockException $exception) {
            throw new ConnectionException(sprintf('OpenID Connect Client: Failed retrieving oAuth token %s: %s', $authorizationIdentifier, $exception->getMessage()), 1559202394);
        }
        return $authorization;
    }
}
