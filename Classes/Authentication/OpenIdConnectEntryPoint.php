<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\ConfigurationException;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Response;
use Neos\Flow\Security\Authentication\EntryPoint\AbstractEntryPoint;
use Psr\Log\LoggerInterface;

final class OpenIdConnectEntryPoint extends AbstractEntryPoint
{
    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @param Request $request
     * @param Response $response
     * @throws ConfigurationException
     * @throws \Exception
     */
    public function startAuthentication(Request $request, Response $response): void
    {
        if (!isset($this->options['serviceName'])) {
            throw new ConfigurationException('OpenID Connect: "serviceName" option was not configured for OpenIdConnectEntryPoint', 1559898606);
        }

        if (isset($this->options['scopes']) && !is_array($this->options['scopes'])) {
            throw new ConfigurationException('OpenID Connect: "scopes" option was not configured correctly for OpenIdConnectEntryPoint', 1560259102);
        }
        $client = new OpenIdConnectClient($this->options['serviceName']);
        $providerUri = $client->authenticate($this->options['serviceName'], $request->getUri(), $this->options['scopes'] ?? []);
        if ($providerUri === null) {
            $this->logger->error(sprintf('OpenID Connect: Flow authentication entry point for service "%s" could not determine a provider URI for redirect', $this->options['serviceName']));
            return;
        }

        $this->logger->info(sprintf('OpenID Connect: Flow authentication entry point redirecting to %s', $providerUri));
        $response->setContent(sprintf('<html lang="en"><head><meta http-equiv="refresh" content="0;url=%s"/><title>OpenID Connect</title></head></html>', htmlentities((string)$providerUri, ENT_QUOTES, 'utf-8')));
        $response->setStatus(303);
        $response->setHeader('Location', (string)$providerUri);
    }
}
