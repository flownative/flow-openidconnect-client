<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\ValidatedIdentityToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;

/**
 * Signs in to the active account whose identifier is the account identifier of the token
 */
#[Flow\Scope('singleton')]
final class PersistedAccountResolver implements AccountResolverInterface
{
    #[Flow\Inject]
    protected AccountRepository $accountRepository;

    public function resolve(ValidatedIdentityToken $validatedIdentityToken, string $authenticationProviderName): ?Account
    {
        $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($validatedIdentityToken->accountIdentifier, $authenticationProviderName);
        // Depending on its collation, the database also finds identifiers which only look similar, for example with accents or trailing spaces.
        if ($account instanceof Account && $account->getAccountIdentifier() === $validatedIdentityToken->accountIdentifier) {
            return $account;
        }
        return null;
    }
}
