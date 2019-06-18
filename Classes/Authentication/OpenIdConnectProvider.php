<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\AuthenticationException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception as SecurityException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Security\Exception\NoSuchRoleException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Psr\Log\LoggerInterface;

final class OpenIdConnectProvider extends AbstractProvider
{
    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var array
     */
    protected $options = [];

    /**
     * @return array
     */
    public function getTokenClassNames(): array
    {
        return [OpenIdConnectToken::class];
    }

    /**
     * @param TokenInterface $authenticationToken
     * @throws InvalidAuthenticationStatusException
     * @throws NoSuchRoleException
     * @throws UnsupportedAuthenticationTokenException
     * @throws AuthenticationException
     */
    public function authenticate(TokenInterface $authenticationToken): void
    {
        if (!$authenticationToken instanceof OpenIdConnectToken) {
            throw new UnsupportedAuthenticationTokenException(sprintf('The OpenID Connect authentication provider cannot authenticate the given token of type %s.', get_class($authenticationToken)), 1559805996);
        }
        if (!isset($this->options['roles'])) {
            throw new \RuntimeException(sprintf('Missing "roles" option in the configuration of OpenID Connect authentication provider'), 1559806095);
        }
        if (!isset($this->options['accountIdentifierTokenValueName'])) {
            $this->options['accountIdentifierTokenValueName'] = 'sub';
        }
        if (!isset($this->options['jwtCookieName'])) {
            $this->options['jwtCookieName'] = 'flownative_oidc_jwt';
        }
        try {
            $identityToken = $authenticationToken->extractIdentityToken($this->options['jwtCookieName']);
        } catch (SecurityException $exception) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        if (!isset($identityToken->values[$this->options['accountIdentifierTokenValueName']])) {
            throw new AuthenticationException(sprintf('Open ID Connect: The identity token provided by the OIDC provider contained no "%s" value, which is needed as an account identifier', $this->options['accountIdentifierTokenValueName']), 1560267246);
        }

        $account = $this->createTransientAccount($identityToken->values[$this->options['accountIdentifierTokenValueName']], $this->options['roles'], $identityToken->asJwt());
        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->logger->debug(sprintf('OpenID Connect: Successfully authenticated account "%s" with authentication provider %s.', $account->getAccountIdentifier(), $account->getAuthenticationProviderName()));
    }

    /**
     * @param string $accountIdentifier
     * @param array $roleIdentifiers
     * @param string $jwt
     * @return Account
     * @throws NoSuchRoleException
     */
    private function createTransientAccount(string $accountIdentifier, array $roleIdentifiers, string $jwt): Account
    {
        $account = new Account();
        $account->setAccountIdentifier($accountIdentifier);
        foreach ($roleIdentifiers as $roleIdentifier) {
            $account->addRole($this->policyService->getRole($roleIdentifier));
        }
        $account->setAuthenticationProviderName($this->name);
        $account->setCredentialsSource(IdentityToken::fromJwt($jwt));
        return $account;
    }
}
