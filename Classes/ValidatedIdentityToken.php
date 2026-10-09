<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Annotations as Flow;

/**
 * An identity token which the IdentityTokenValidator has accepted, together with the account identifier taken from it
 *
 * Code which receives one can trust the claims of the token, so instances are only created by the validator.
 */
#[Flow\Proxy(false)]
final readonly class ValidatedIdentityToken
{
    public function __construct(
        public IdentityToken $identityToken,
        public string $accountIdentifier,
    ) {
    }
}
