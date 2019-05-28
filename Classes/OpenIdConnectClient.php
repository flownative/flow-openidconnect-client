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

class OpenIdConnectClient
{
    /**
     * @var string
     */
    protected $serviceName;

    /**
     * @var array
     */
    protected $options;

    /**
     * @Flow\InjectConfiguration
     * @var array
     */
    protected $settings;

    /**
     * @var OAuthClient
     */
    protected $oAuthClient;

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

        foreach (['clientId', 'clientSecret', 'authorizationEndpoint', 'tokenEndpoint'] as $optionName) {
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
