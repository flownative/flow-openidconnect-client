<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Annotations as Flow;

/**
 * Creates OpenID Connect clients for a configured service
 *
 * The authentication provider, token and entry point get their clients from this
 * factory. It is not final, so that tests can replace it with a stub.
 */
#[Flow\Scope('singleton')]
class OpenIdConnectClientFactory
{
    public function create(string $serviceName): OpenIdConnectClient
    {
        return new OpenIdConnectClient($serviceName);
    }
}
