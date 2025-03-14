<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

final class TokenSet
{
    public function __construct(
        public readonly IdentityToken $identityToken,
        public readonly string $refreshToken,
    )
    {
    }
}
