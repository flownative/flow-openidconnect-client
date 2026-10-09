<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\RequestOptions;
use Neos\Flow\Annotations as Flow;
use RuntimeException;

/**
 * Creates HTTP clients with the time limits of the setting "httpClient", so that an identity provider which doesn't answer can't
 * keep a request, or a worker, waiting until PHP gives up
 */
#[Flow\Scope('singleton')]
final class HttpClientFactory implements HttpClientFactoryInterface
{
    private float $connectTimeout;

    private float $timeout;

    #[Flow\InjectConfiguration(path: 'httpClient')]
    protected array $settings = [];

    /**
     * The settings are checked once, when the factory is created, instead of in the middle of an authentication
     */
    public function initializeObject(): void
    {
        $this->connectTimeout = $this->getSeconds('connectTimeout', 5);
        $this->timeout = $this->getSeconds('timeout', 10);
    }

    public function create(): ClientInterface
    {
        return new Client([
            RequestOptions::CONNECT_TIMEOUT => $this->connectTimeout,
            RequestOptions::TIMEOUT => $this->timeout,
        ]);
    }

    /**
     * Guzzle waits without a limit for zero seconds, so only a positive number is accepted
     */
    private function getSeconds(string $settingName, float $default): float
    {
        $seconds = $this->settings[$settingName] ?? $default;
        if ((!is_int($seconds) && !is_float($seconds)) || $seconds <= 0) {
            throw new RuntimeException(sprintf('OpenID Connect Client: The setting "httpClient.%s" must be a positive number of seconds', $settingName), 1791540877);
        }
        return (float)$seconds;
    }
}
