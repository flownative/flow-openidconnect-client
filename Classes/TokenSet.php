<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class TokenSet
{
    public function __construct(
        public readonly IdentityToken $identityToken,
        public readonly string $refreshToken,
    ) {
    }
}
