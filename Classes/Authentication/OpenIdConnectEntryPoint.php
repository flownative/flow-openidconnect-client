<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OpenIdConnect\Client\ConfigurationException;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\ContentStream;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Authentication\EntryPoint\AbstractEntryPoint;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

final class OpenIdConnectEntryPoint extends AbstractEntryPoint
{
    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws ConfigurationException
     */
    public function startAuthentication(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $this->validateOptions();
        $this->logger->debug(sprintf('OpenID Connect: OpenIdConnectEntryPoint starting authentication for service "%s" ...', $this->options['serviceName']), LogEnvironment::fromMethodName(__METHOD__));

        if ($this->hasAuthorizationHeader($request)) {
            $this->logger->debug('OpenID Connect: OpenIdConnectEntryPoint detected "Authorization" header', LogEnvironment::fromMethodName(__METHOD__));
        }

        $client = new OpenIdConnectClient($this->options['serviceName']);
        try {
            $providerUri = $client->startAuthorization($this->options['serviceName'], $request->getUri(), $this->options['scope'] ?? '');
        } catch (OAuthClientException | ServiceException $exception) {
            $this->logger->error(sprintf('OpenID Connect: Authentication for service "%s" failed: %s', $this->options['serviceName'], $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return $response;
        }

        $this->logger->info(sprintf('OpenID Connect: OpenIdConnectEntryPoint for service "%s" redirecting to %s', $this->options['serviceName'], $providerUri), LogEnvironment::fromMethodName(__METHOD__));

        $body = ContentStream::fromContents(sprintf('<html lang="en"><head><meta http-equiv="refresh" content="0;url=%s"/><title>OpenID Connect</title></head></html>', htmlentities((string)$providerUri, ENT_QUOTES, 'utf-8')));
        return $response->withBody($body)->withStatus(303)->withHeader('Location', (string)$providerUri);
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

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    private function hasAuthorizationHeader(ServerRequestInterface $request): bool
    {
        $authorizationHeader = null;
        if ($request->hasHeader('Authorization')) {
            $authorizationHeader = $request->getHeader('Authorization');
        } elseif ($request->hasHeader('authorization')) {
            $authorizationHeader = $request->getHeader('Authorization');
        }

        if (is_array($authorizationHeader)) {
            $authorizationHeader = reset($authorizationHeader);
        }
        return $authorizationHeader !== null;
    }
}
