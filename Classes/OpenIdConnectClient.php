<?php

namespace Flownative\OpenIdConnect\Client;

use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Flownative\OAuth2\Client\OAuthToken;
use Flownative\OpenIdConnect\Client\OAuthClient as OAuthClient;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Uri;
use Neos\Flow\Log\SystemLoggerInterface;
use Neos\Flow\Session\Exception\SessionNotStartedException;
use Neos\Utility\Arrays;

final class OpenIdConnectClient
{
    /**
     * @var string
     */
    private $serviceName;

    /**
     * @var array
     */
    private $options;

    /**
     * @Flow\InjectConfiguration
     * @var array
     */
    protected $settings;

    /**
     * @var OAuthClient
     */
    private $oAuthClient;

    /**
     * @var array
     */
    private $jwks = [];

    /**
     * @Flow\Inject
     * @var SystemLoggerInterface
     */
    protected $logger;

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
    }

    /**
     * Prepare options and run auto-discovery, if configured
     *
     * @throws ConnectionException
     * @throws ConfigurationException
     */
    protected function initializeObject(): void
    {
        if (!isset($this->settings['services'][$this->serviceName])) {
            throw new ConfigurationException(sprintf('OpenID Connect client: No configuration found for service "%s".', $this->serviceName), 1554914085);
        }
        if (!isset($this->settings['services'][$this->serviceName]['options'])) {
            throw new ConfigurationException(sprintf('OpenID Connect client: Missing options in configuration for service "%s".', $this->serviceName), 1554914112);
        }
        if (!is_array($this->settings['services'][$this->serviceName]['options'])) {
            throw new ConfigurationException(sprintf('OpenID Connect client: Invalid configuration for service "%s", options must be an array.', $this->serviceName), 1554914157);
        }
        $this->options = Arrays::arrayMergeRecursiveOverrule(self::DEFAULT_OPTIONS, $this->settings['services'][$this->serviceName]['options']);
        if (isset($this->options['discoveryUri'])) {
            $this->amendOptionsWithDiscovery($this->options['discoveryUri']);
        }

        foreach (['clientId', 'clientSecret', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri'] as $optionName) {
            if (empty($this->options[$optionName])) {
                throw new ConfigurationException(sprintf('OpenID Connect client: Required option "%s" is not configured for service "%s".', $optionName, $this->serviceName), 1554968498);
            }
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
     * @param Uri $returnToUri
     * @return Uri|null
     * @throws AuthenticationException
     */
    public function authenticate(Uri $returnToUri): ?Uri
    {
        try {
            $oAuthToken = $this->oAuthClient->getOAuthToken();
            if ($oAuthToken instanceof OAuthToken) {
                return null;
            }
            $uri = $this->oAuthClient->startAuthorization($this->options['clientId'], $this->options['clientSecret'], $returnToUri, ['openid']);
        } catch (OptimisticLockException | ORMException | SessionNotStartedException $e) {
            throw new AuthenticationException(sprintf('OpenID Connect client: Authentication failed with error %s.', $e->getMessage()));
        }
        return $uri;
    }

    /**
     * Returns the current oAuth token, if any
     *
     * @return OAuthToken|null
     * @throws ConnectionException
     */
    public function getOAuthToken(): ?OAuthToken
    {
        try {
            $oAuthToken = $this->oAuthClient->getOAuthToken();
        } catch (ORMException | OptimisticLockException $exception) {
            throw new ConnectionException(sprintf('OpenID Connect client: Failed retrieving oAuth token: %s', $exception->getMessage()), 1559202394);
        }
        return $oAuthToken;
    }

    /**
     * Returns the current OpenId Connect Identity Token
     *
     * @return IdentityToken
     * @throws ConnectionException
     * @throws ServiceException
     */
    public function getIdentityToken(): IdentityToken
    {
        $oAuthToken = $this->getOAuthToken();
        if (!$oAuthToken instanceof OAuthToken) {
            throw new ServiceException('OpenID Connect client: No oAuth token found', 1559202394);
        }
        $tokenValues = $oAuthToken->tokenValues;
        if (!isset($tokenValues['id_token'])) {
            throw new ServiceException('OpenID Connect client: No id_token found in values of current oAuth token', 1559208674);
        }

        $identityToken = IdentityToken::fromJWT($tokenValues['id_token']);
        if (!$identityToken->hasValidSignature($this->getJwks())) {
            throw new ServiceException('OpenID Connect client: The signature for the retrieved ID token was invalid', 1559210845);
        }
        return$identityToken;
    }

    /**
     * Retrieves the JSON Web Keys from the endpoint configured via the "jwksUri" option
     *
     * @return array
     * @throws ConnectionException
     * @throws ServiceException
     * @see https://tools.ietf.org/html/rfc7517
     */
    private function getJwks(): array
    {
        if (count($this->jwks)) {
            return $this->jwks;
        }

        $httpClient = new HttpClient();
        try {
            $response = $httpClient->request('GET', $this->options['jwksUri']);
        } catch (GuzzleException $e) {
            throw new ConnectionException(sprintf('OpenID Connect: Failed retrieving JWKs from %s: %s', $this->options['jwksUri'], $e->getMessage()), 1559211266);
        }

        $response = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
        if (!is_array($response) || !isset($response['keys'])) {
            throw new ServiceException(sprintf('OpenID Connect: Failed decoding response while retrieving JWKs from %s', $this->options['jwksUri']), 1559211340);
        }
        $this->jwks = $response['keys'];
        return $this->jwks;
    }

    /**
     * @param string $discoveryUri
     * @throws ConnectionException
     */
    private function amendOptionsWithDiscovery(string $discoveryUri): void
    {
        $httpClient = new HttpClient();

        try {
            $response = $httpClient->request('GET', $discoveryUri);
        } catch (GuzzleException $e) {
            throw new ConnectionException(sprintf('OpenID Connect: Failed discovering options at %s: %s', $discoveryUri, $e->getMessage()), 1554902567);
        }

        $discoveredOptions = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
        if (!is_array($discoveredOptions)) {
            throw new ConnectionException(sprintf('OpenID Connect: Discovery endpoint returned invalid response.'), 1554903349);
        }

        foreach ($discoveredOptions as $optionName => $optionValue) {
            if (isset(self::DISCOVERY_OPTIONS_MAPPING[$optionName])) {
                $this->options[self::DISCOVERY_OPTIONS_MAPPING[$optionName]] = $optionValue;
            }
        }
    }
}
