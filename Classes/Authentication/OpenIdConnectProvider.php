<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\AuthenticationException;
use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\PsrSystemLoggerInterface;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Exception as SecurityException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Security\Exception\NoSuchRoleException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Flow\Security\Policy\Role;

final class OpenIdConnectProvider extends AbstractProvider
{
    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var PsrSystemLoggerInterface
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
     * @throws AuthenticationException
     * @throws ConnectionException
     * @throws InvalidAuthenticationStatusException
     * @throws NoSuchRoleException
     * @throws ServiceException
     * @throws UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken): void
    {
        if (!$authenticationToken instanceof OpenIdConnectToken) {
            throw new UnsupportedAuthenticationTokenException(sprintf('The OpenID Connect authentication provider cannot authenticate the given token of type %s.', get_class($authenticationToken)), 1559805996);
        }
        if (!isset($this->options['roles']) && !isset($this->options['rolesFromClaims'])) {
            throw new \RuntimeException(sprintf('Either "roles" or "rolesFromClaims" must be specified in the configuration of OpenID Connect authentication provider'), 1559806095);
        }
        if (!isset($this->options['serviceName'])) {
            throw new \RuntimeException(sprintf('Missing "serviceName" option in the configuration of OpenID Connect authentication provider'), 1561480057);
        }
        if (!isset($this->options['accountIdentifierTokenValueName'])) {
            $this->options['accountIdentifierTokenValueName'] = 'sub';
        }
        if (!isset($this->options['jwtCookieName'])) {
            $this->options['jwtCookieName'] = 'flownative_oidc_jwt';
        }
        try {
            $jwks = (new OpenIdConnectClient($this->options['serviceName']))->getJwks();
            $identityToken = $authenticationToken->extractIdentityTokenFromRequest($this->options['jwtCookieName']);
            if (!$identityToken->hasValidSignature($jwks)) {
                throw new SecurityException(sprintf('Open ID Connect: The identity token provided by the OIDC provider had an invalid signature'), 1561479176);
            }
            $this->logger->debug(sprintf('OpenID Connect: Successfully verified signature of identity token with %s value "%s"', $this->options['accountIdentifierTokenValueName'], $identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? 'unknown'), LogEnvironment::fromMethodName(__METHOD__));
        } catch (SecurityException\AuthenticationRequiredException $exception) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            return;
        } catch (SecurityException $exception) {
            if ($authenticationToken->getAuthenticationStatus() === TokenInterface::AUTHENTICATION_SUCCESSFUL) {
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            }
            $this->logger->notice(sprintf('OpenID Connect: The authentication provider caught an exception: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        if ($identityToken->isExpiredAt(new \DateTimeImmutable())) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            $this->logger->info(sprintf('OpenID Connect: The JWT token "%s" is expired, need to re-authenticate', $identityToken->values[$this->options['accountIdentifierTokenValueName']]), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        if (!isset($identityToken->values[$this->options['accountIdentifierTokenValueName']])) {
            throw new AuthenticationException(sprintf('Open ID Connect: The identity token provided by the OIDC provider contained no "%s" value, which is needed as an account identifier', $this->options['accountIdentifierTokenValueName']), 1560267246);
        }

        $roleIdentifiers = $this->getConfiguredRoles($identityToken);

        $account = $this->createTransientAccount($identityToken->values[$this->options['accountIdentifierTokenValueName']], $roleIdentifiers, $identityToken->asJwt());
        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->logger->info(sprintf('OpenID Connect: Successfully authenticated account "%s" with authentication provider %s. Roles: %s', $account->getAccountIdentifier(), $account->getAuthenticationProviderName(), implode(', ', $this->getConfiguredRoles($identityToken))), LogEnvironment::fromMethodName(__METHOD__));

        $this->emitAuthenticated($authenticationToken, $identityToken, $this->policyService->getRoles());
    }

    /**
     * @param TokenInterface $authenticationToken
     * @param IdentityToken $identityToken
     * @param Role[] $roles
     * @return void
     * @Flow\Signal()
     */
    public function emitAuthenticated(TokenInterface $authenticationToken, IdentityToken $identityToken, array $roles): void
    {
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

    /**
     * @param IdentityToken $identityToken
     * @return array
     */
    private function getConfiguredRoles(IdentityToken $identityToken): array
    {
        if (isset($this->options['roles'])) {
            return $this->options['roles'];
        }

        $roleIdentifiers = [];

        foreach ($this->options['rolesFromClaims'] as $claim) {
            if (!isset($identityToken->values[$claim])) {
                $this->logger->debug(sprintf('OpenID Connect: getConfiguredRoles() Identity token (%s) contained no claim "%s"', $identityToken->values['sub'] ?? '', $claim), LogEnvironment::fromMethodName(__METHOD__));
                continue;
            }
            if (!is_array($identityToken->values[$claim])) {
                $this->logger->error(sprintf('OpenID Connect: Failed retrieving roles from identity token (%s) because the claim "%s" was not an array as expected.', $identityToken->values['sub'] ?? '', $claim), LogEnvironment::fromMethodName(__METHOD__));
                continue;
            }

            foreach ($identityToken->values[$claim] as $i => $roleIdentifier) {
                if ($this->policyService->hasRole($roleIdentifier)) {
                    $roleIdentifiers[] = $roleIdentifier;
                } else {
                    $this->logger->error(sprintf('OpenID Connect: Ignoring role "%s" from identity token (%s) because there is no such role configured in Flow.', $roleIdentifier, $identityToken->values['sub'] ?? ''), LogEnvironment::fromMethodName(__METHOD__));
                }
            }

        }

        return array_unique($roleIdentifiers);
    }
}
