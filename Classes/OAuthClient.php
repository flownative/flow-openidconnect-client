<?php

namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Annotations as Flow;

class OAuthClient extends \Flownative\OAuth2\Client\OAuthClient
{
    /**
     * @Flow\InjectConfiguration(path="http.baseUri", package="Neos.Flow")
     * @var string
     */
    protected $flowBaseUriSetting;

    /**
     * @var array
     */
    protected $options;

    /**
     * @param array $options
     */
    public function setOptions(array $options): void
    {
        $this->options = $options;
    }

    /**
     * @return string
     */
    public function getBaseUri(): string
    {
        return $this->options['issuer'];
    }

    /**
     * Returns the OAuth service endpoint for authorizing a token.
     * Override this method if needed.
     *
     * @return string
     */
    public function getAuthorizeTokenUri(): string
    {
        return $this->options['authorizationEndpoint'];
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->options['clientId'];
    }

    /**
     * @return string
     */
    public function getServiceName(): string
    {
        return 'OpenIdConnect';
    }
}
