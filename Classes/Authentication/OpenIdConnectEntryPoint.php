<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OpenIdConnect\Client\ConfigurationException;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Response;
use Neos\Flow\Log\PsrSystemLoggerInterface;
use Neos\Flow\Security\Authentication\EntryPoint\AbstractEntryPoint;

final class OpenIdConnectEntryPoint extends AbstractEntryPoint
{
    /**
     * @Flow\Inject
     * @var PsrSystemLoggerInterface
     */
    protected $logger;

    /**
     * @param Request $request
     * @param Response $response
     * @throws ConfigurationException
     */
    public function startAuthentication(Request $request, Response $response): void
    {
        $this->validateOptions();
        $this->logger->debug(sprintf('OpenID Connect: OpenIdConnectEntryPoint starting authentication for service "%s" ...', $this->options['serviceName']));

        $client = new OpenIdConnectClient($this->options['serviceName']);
        try {
            $providerUri = $client->startAuthorization($this->options['serviceName'], $request->getUri(), $this->options['scope'] ?? '');
        } catch (OAuthClientException | ServiceException $exception) {
            $this->logger->error(sprintf('OpenID Connect: Authentication for service "%s" failed: %s', $this->options['serviceName'], $exception->getMessage()));
            return;
        }

        $this->logger->info(sprintf('OpenID Connect: OpenIdConnectEntryPoint for service "%s" redirecting to %s', $this->options['serviceName'], $providerUri));
        $response->setContent(sprintf('<html lang="en"><head><meta http-equiv="refresh" content="0;url=%s"/><title>OpenID Connect</title></head></html>', htmlentities((string)$providerUri, ENT_QUOTES, 'utf-8')));
        $response->setStatus(303);
        $response->setHeader('Location', (string)$providerUri);
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
    }
}
