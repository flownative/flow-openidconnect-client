<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

/**
 * Tells the state signer of a service which hosts belong to a tenant of the application
 *
 * Configure it for host patterns with a wildcard, see the "stateSigning" option of a service. Without it, a state is signed for every
 * host which matches the patterns, including one which a request names in its Host header but which serves no tenant.
 */
interface KnownTargetHostsInterface
{
    /**
     * @param string $targetHost In lower case, with the port if it is not the default one, such as "acme.example.com:8443"
     */
    public function isKnownTargetHost(string $targetHost): bool;
}
