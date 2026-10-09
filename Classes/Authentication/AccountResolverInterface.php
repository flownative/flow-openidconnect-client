<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\ValidatedIdentityToken;
use Neos\Flow\Security\Account;

/**
 * Decides which persisted account an identity signs in to, when the provider authenticates an OpenIdConnectSessionToken
 *
 * The provider calls it only with a token which passed all checks. An application implements it to admit identities in its own
 * way, for example by linking an identity to an existing person through a verified email address on the first sign-in.
 */
interface AccountResolverInterface
{
    /**
     * Returns the account to sign in to, or null if the identity is not admitted
     *
     * @param string $authenticationProviderName The provider name of the account: the "lookupProviderName" option, or the name of the authentication provider
     */
    public function resolve(ValidatedIdentityToken $validatedIdentityToken, string $authenticationProviderName): ?Account;
}
