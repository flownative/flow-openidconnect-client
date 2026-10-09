<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use GuzzleHttp\ClientInterface;

/**
 * Creates the HTTP client for all requests of this package to the identity provider: discovery, keys, codes and tokens
 *
 * Replace the implementation in Objects.yaml to use a proxy, or in tests a client which answers without the network.
 */
interface HttpClientFactoryInterface
{
    public function create(): ClientInterface;
}
