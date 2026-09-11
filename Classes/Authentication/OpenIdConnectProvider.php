<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Authentication;

use DateInterval;
use DateTimeImmutable;
use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClientFactory;
use Flownative\OpenIdConnect\Client\ServiceException;
use Neos\Cache\Exception as CacheException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Configuration\Exception\InvalidConfigurationTypeException;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception as SecurityException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Security\Exception\NoSuchRoleException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Flow\Security\Policy\Role;
use Neos\Flow\Session\SessionInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;

/**
 * Authenticates accounts with identity tokens or access tokens issued by an OpenID Connect provider
 *
 * A token is only accepted if its signature is valid, it was issued by the expected issuer for
 * the expected audience, and it is valid at the current time. Tokens which fail one of these
 * checks lead to wrong credentials and are logged, but do not throw an exception.
 */
final class OpenIdConnectProvider extends AbstractProvider
{
    /**
     * Seconds which compensate for clock differences between the identity provider and this application
     */
    private const int DEFAULT_LEEWAY = 60;

    #[Flow\Inject]
    protected PolicyService $policyService;

    /**
     * Not lazy, because a named injection would otherwise receive a dependency proxy which does not match the type.
     */
    #[Flow\Inject(name: 'Neos.Flow:SecurityLogger', lazy: false)]
    protected ?LoggerInterface $logger = null;

    #[Flow\Inject]
    protected AccountRepository $accountRepository;

    #[Flow\Inject]
    protected SessionInterface $session;

    #[Flow\Inject]
    protected OpenIdConnectClientFactory $openIdConnectClientFactory;

    public function getTokenClassNames(): array
    {
        return [OpenIdConnectToken::class];
    }

    /**
     * @throws CacheException
     * @throws InvalidAuthenticationStatusException
     * @throws InvalidConfigurationTypeException
     * @throws NoSuchRoleException
     * @throws UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken): void
    {
        if (!$authenticationToken instanceof OpenIdConnectToken) {
            throw new UnsupportedAuthenticationTokenException(sprintf('The OpenID Connect authentication provider cannot authenticate the given token of type %s.', get_class($authenticationToken)), 1559805996);
        }
        if (!isset($this->options['roles']) && !isset($this->options['rolesFromClaims']) && !isset($this->options['addRolesFromExistingAccount'])) {
            throw new RuntimeException('Either "roles", "rolesFromClaims" or "addRolesFromExistingAccount" must be specified in the configuration of OpenID Connect authentication provider', 1559806095);
        }
        if (!isset($this->options['serviceName'])) {
            throw new RuntimeException('Missing "serviceName" option in the configuration of OpenID Connect authentication provider', 1561480057);
        }
        if (!isset($this->options['accountIdentifierTokenValueName'])) {
            $this->options['accountIdentifierTokenValueName'] = 'sub';
        }
        if (!isset($this->options['jwtCookieName'])) {
            $this->options['jwtCookieName'] = 'flownative_oidc_jwt';
        }
        $leeway = $this->options['leeway'] ?? self::DEFAULT_LEEWAY;
        if (!is_int($leeway) || $leeway < 0) {
            throw new RuntimeException('The "leeway" option in the configuration of OpenID Connect authentication provider must be zero or a positive number of seconds', 1789122177);
        }
        $leewayInterval = new DateInterval('PT' . $leeway . 'S');

        try {
            $identityToken = $authenticationToken->extractIdentityTokenFromRequest($this->options['jwtCookieName']);
        } catch (AuthenticationRequiredException) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            return;
        } catch (SecurityException $exception) {
            $this->logger?->notice(sprintf('OpenID Connect: Could not extract an identity token from the request: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        try {
            // Creating the client may already contact the identity provider for discovery.
            $client = $this->openIdConnectClientFactory->create($this->options['serviceName']);
            $jwks = $client->getJwks();
        } catch (ConnectionException|ServiceException $exception) {
            $this->logger?->error(sprintf('OpenID Connect: Could not retrieve the configuration or the JSON Web Key Set of service "%s": %s', $this->options['serviceName'], $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        $now = new DateTimeImmutable();
        $validationTime = $now->add($leewayInterval);
        if (!$this->verifySignature($identityToken, $jwks) || !$this->hasAcceptableClaims($identityToken, $client->getOptions(), $validationTime)) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        $refreshToken = $authenticationToken->getRefreshToken();
        if ($refreshToken !== '') {
            if ($this->session->canBeResumed()) {
                $this->session->resume();
            }
            if (!$this->session->isStarted()) {
                $this->session->start();
            }

            if ($this->session->isStarted()) {
                $this->logger?->debug('OpenID Connect: Set refresh token in session', LogEnvironment::fromMethodName(__METHOD__));
                $this->session->putData('flownative_oidc_refresh', $refreshToken);
            } else {
                $this->logger?->debug('OpenID Connect: Could not store refresh token in session', LogEnvironment::fromMethodName(__METHOD__));
            }
        }

        if ($identityToken->isExpiredAt($now->sub($leewayInterval))) {
            $refreshedIdentityToken = $this->refreshExpiredIdentityToken($identityToken, $client);
            if ($refreshedIdentityToken !== $identityToken) {
                if (!$this->verifySignature($refreshedIdentityToken, $jwks) || !$this->hasAcceptableClaims($refreshedIdentityToken, $client->getOptions(), $validationTime)) {
                    $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                    return;
                }
                $identityToken = $refreshedIdentityToken;
            }
        }

        if ($identityToken->isExpiredAt($now->sub($leewayInterval))) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            $this->logger?->info(sprintf('OpenID Connect: The identity token %s is expired, need to re-authenticate', self::describeValue($identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null)), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        $roleIdentifiers = $this->getConfiguredRoles($identityToken);

        $account = $this->createTransientAccount($identityToken->values[$this->options['accountIdentifierTokenValueName']], $roleIdentifiers, $identityToken->asJwt());
        $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->logger?->debug(sprintf('OpenID Connect: Successfully authenticated account %s with authentication provider %s. Roles: %s', self::describeValue($account->getAccountIdentifier()), $account->getAuthenticationProviderName(), implode(', ', $roleIdentifiers)), LogEnvironment::fromMethodName(__METHOD__));

        $this->emitAuthenticated($authenticationToken, $identityToken, $this->policyService->getRoles());
    }

    public function getServiceName(): string
    {
        return $this->options['serviceName'] ?? '';
    }

    /**
     * @param Role[] $roles
     */
    #[Flow\Signal]
    public function emitAuthenticated(TokenInterface $authenticationToken, IdentityToken $identityToken, array $roles): void
    {
    }

    private function verifySignature(IdentityToken $identityToken, array $jwks): bool
    {
        try {
            if ($identityToken->hasValidSignature($jwks)) {
                return true;
            }
            $this->logger?->notice('OpenID Connect: The identity token has an invalid signature', LogEnvironment::fromMethodName(__METHOD__));
        } catch (ServiceException $exception) {
            $this->logger?->notice(sprintf('OpenID Connect: Could not verify the signature of the identity token: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
        }
        return false;
    }

    /**
     * Tries to replace an expired identity token with a new one, using the refresh token stored in the session
     *
     * Returns the given token if it cannot be refreshed.
     */
    private function refreshExpiredIdentityToken(IdentityToken $identityToken, OpenIdConnectClient $client): IdentityToken
    {
        if ($this->session->canBeResumed()) {
            $this->session->resume();
        }
        if (!$this->session->isStarted()) {
            $this->session->start();
        }
        if (!$this->session->isStarted()) {
            return $identityToken;
        }

        $accountIdentifier = self::describeValue($identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null);
        $refreshToken = (string)$this->session->getData('flownative_oidc_refresh');
        if ($refreshToken === '') {
            $this->logger?->info(sprintf('OpenID Connect: The identity token %s is expired, no refresh token in session', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
            return $identityToken;
        }

        $this->logger?->info(sprintf('OpenID Connect: The identity token %s is expired, trying to refresh it with the refresh token from the session', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
        try {
            $tokenSet = $client->refreshIdentityToken($identityToken, $refreshToken);
        } catch (ConnectionException|ServiceException $exception) {
            $this->logger?->info(sprintf('OpenID Connect: Could not refresh the identity token: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return $identityToken;
        }

        if ($tokenSet->refreshToken !== '') {
            $this->logger?->debug('OpenID Connect: Set new refresh token in session', LogEnvironment::fromMethodName(__METHOD__));
            $this->session->putData('flownative_oidc_refresh', $tokenSet->refreshToken);
        } else {
            $this->logger?->info('OpenID Connect: Did not receive new refresh token to set in session', LogEnvironment::fromMethodName(__METHOD__));
        }
        return $tokenSet->identityToken;
    }

    /**
     * @param DateTimeImmutable $validationTime The current time plus the leeway for tokens issued by a clock which is ahead
     */
    private function hasAcceptableClaims(IdentityToken $identityToken, array $clientOptions, DateTimeImmutable $validationTime): bool
    {
        $rejectionReason = $this->getClaimsRejectionReason($identityToken, $clientOptions, $validationTime);
        if ($rejectionReason === null) {
            return true;
        }
        $this->logger?->notice(sprintf('OpenID Connect: Rejected the identity token for service "%s", because %s', $this->options['serviceName'], $rejectionReason), LogEnvironment::fromMethodName(__METHOD__));
        return false;
    }

    /**
     * Returns why the claims of the given token are not acceptable, or null if they are
     *
     * The expiration time is checked separately, because an expired token may still be refreshed.
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     */
    private function getClaimsRejectionReason(IdentityToken $identityToken, array $clientOptions, DateTimeImmutable $validationTime): ?string
    {
        $issuerMatches = false;
        foreach ($this->getExpectedIssuers($clientOptions, $identityToken) as $expectedIssuer) {
            if ($identityToken->isIssuedBy($expectedIssuer)) {
                $issuerMatches = true;
                break;
            }
        }
        if (!$issuerMatches) {
            return sprintf('its issuer %s does not match the expected issuer', self::describeValue($identityToken->values['iss'] ?? null));
        }

        $expectedAudiences = $this->getExpectedAudiences($clientOptions);
        if (!$this->audienceMatches($expectedAudiences, $identityToken)) {
            return sprintf('its audience %s contains none of %s', self::describeValue($identityToken->values['aud'] ?? null), self::describeValue($expectedAudiences));
        }

        if ($identityToken->isNotYetValidAt($validationTime)) {
            return 'it is not valid yet';
        }

        $accountIdentifier = $identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null;
        if (!is_string($accountIdentifier) || $accountIdentifier === '') {
            return sprintf('its claim "%s", which is used as account identifier, is missing or not a string', $this->options['accountIdentifierTokenValueName']);
        }
        return null;
    }

    /**
     * Returns the issuers of which one must have issued the token
     *
     * The "issuer" option of the provider takes precedence over the issuer of the service. Issuers
     * containing the placeholder "{tenantid}", used for multi-tenant applications of Microsoft Entra
     * ID, are resolved with the "tid" claim of the token and left out if the token has no valid "tid".
     *
     * @return string[]
     */
    private function getExpectedIssuers(array $clientOptions, IdentityToken $identityToken): array
    {
        $issuers = $this->options['issuer'] ?? $clientOptions['issuer'] ?? [];
        if (is_string($issuers)) {
            $issuers = [$issuers];
        }
        if (is_array($issuers)) {
            $issuers = array_values(array_filter($issuers, static fn (mixed $issuer): bool => is_string($issuer) && $issuer !== ''));
        }
        if (!is_array($issuers) || $issuers === []) {
            throw new RuntimeException(sprintf('OpenID Connect: The issuer of service "%s" is unknown. Configure the "issuer" option of the authentication provider or the service, or a "discoveryUri" for the service', $this->options['serviceName']), 1789122175);
        }

        $tenantIdentifier = $identityToken->values['tid'] ?? null;
        $hasValidTenantIdentifier = is_string($tenantIdentifier) && preg_match('/^[a-zA-Z0-9-]+\z/', $tenantIdentifier) === 1;

        $resolvedIssuers = [];
        foreach ($issuers as $issuer) {
            if (!str_contains($issuer, '{tenantid}')) {
                $resolvedIssuers[] = $issuer;
            } elseif ($hasValidTenantIdentifier) {
                $resolvedIssuers[] = str_replace('{tenantid}', $tenantIdentifier, $issuer);
            }
        }
        return $resolvedIssuers;
    }

    /**
     * Returns the audiences of which a token must contain at least one: the "audience" option or the client id of the service
     *
     * @return string[]
     */
    private function getExpectedAudiences(array $clientOptions): array
    {
        $audiences = $this->options['audience'] ?? $clientOptions['clientId'] ?? [];
        if (is_string($audiences)) {
            $audiences = [$audiences];
        }
        if (is_array($audiences)) {
            $audiences = array_values(array_filter($audiences, static fn (mixed $audience): bool => is_string($audience) && $audience !== ''));
        }
        if (!is_array($audiences) || $audiences === []) {
            throw new RuntimeException(sprintf('OpenID Connect: No audience is configured for the authentication provider of service "%s". Configure the "audience" option or the "clientId" of the service', $this->options['serviceName']), 1789122176);
        }
        return $audiences;
    }

    /**
     * @param string[] $expectedAudiences
     */
    private function audienceMatches(array $expectedAudiences, IdentityToken $identityToken): bool
    {
        foreach ($expectedAudiences as $expectedAudience) {
            if ($identityToken->audienceContains($expectedAudience)) {
                return true;
            }
        }
        return false;
    }

    /**
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
        $account->setCredentialsSource($jwt);
        return $account;
    }

    private function getConfiguredRoles(IdentityToken $identityToken): array
    {
        $roleIdentifiers = [];
        $subject = self::describeValue($identityToken->values['sub'] ?? null);

        if (isset($this->options['roles']) && is_array($this->options['roles'])) {
            $roleIdentifiers = $this->options['roles'];
            $this->logger?->debug(sprintf('OpenID Connect: Adding the following fixed configured roles for identity token (%s): %s', $subject, implode(', ', $roleIdentifiers)), LogEnvironment::fromMethodName(__METHOD__));
        }

        if (isset($this->options['rolesFromClaims']) && is_array($this->options['rolesFromClaims'])) {
            foreach ($this->options['rolesFromClaims'] as $claim) {
                $mapping = null;
                if (is_array($claim)) {
                    if (!array_key_exists('mapping', $claim)) {
                        throw new RuntimeException('If "rolesFromClaims" are specified as array, a "mapping" has to be provided', 1623421601);
                    }
                    $mapping = $claim['mapping'];
                    if (!is_array($mapping)) {
                        throw new RuntimeException(sprintf('If "rolesFromClaims" are specified as array, a "mapping" has to be provided as array, given: %s', gettype($mapping)), 1623656982);
                    }
                    if (!array_key_exists('name', $claim)) {
                        throw new RuntimeException('If "rolesFromClaims" are specified as array, a "name" has to be provided', 1623421648);
                    }
                    $claim = $claim['name'];
                }
                if (!isset($identityToken->values[$claim])) {
                    $this->logger?->debug(sprintf('OpenID Connect: Identity token (%s) contained no claim "%s"', $subject, $claim), LogEnvironment::fromMethodName(__METHOD__));
                    continue;
                }
                if (!is_array($identityToken->values[$claim])) {
                    $this->logger?->error(sprintf('OpenID Connect: Failed retrieving roles from identity token (%s) because the claim "%s" was not an array as expected.', $subject, $claim), LogEnvironment::fromMethodName(__METHOD__));
                    continue;
                }

                foreach ($identityToken->values[$claim] as $roleIdentifier) {
                    if (!is_string($roleIdentifier)) {
                        $this->logger?->debug(sprintf('OpenID Connect: Ignoring role %s from identity token (%s) because it is not a string.', self::describeValue($roleIdentifier), $subject), LogEnvironment::fromMethodName(__METHOD__));
                        continue;
                    }
                    if ($mapping !== null) {
                        if (!array_key_exists($roleIdentifier, $mapping)) {
                            $this->logger?->debug(sprintf('OpenID Connect: Ignoring role %s from identity token (%s) because there is no corresponding mapping configured.', self::describeValue($roleIdentifier), $subject), LogEnvironment::fromMethodName(__METHOD__));
                            continue;
                        }
                        $roleIdentifier = $mapping[$roleIdentifier];
                    }
                    if ($this->policyService->hasRole($roleIdentifier)) {
                        $roleIdentifiers[] = $roleIdentifier;
                    } else {
                        $this->logger?->debug(sprintf('OpenID Connect: Ignoring role %s from identity token (%s) because there is no such role configured in Flow.', self::describeValue($roleIdentifier), $subject), LogEnvironment::fromMethodName(__METHOD__));
                    }
                }
            }
        }
        if (isset($this->options['addRolesFromExistingAccount']) && $this->options['addRolesFromExistingAccount'] === true) {
            $accountIdentifier = $identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null;
            if (!is_string($accountIdentifier)) {
                $this->logger?->error(sprintf('OpenID Connect: Failed using account identifier from identity token (%s) because the configured claim "%s" does not exist.', $subject, $this->options['accountIdentifierTokenValueName']), LogEnvironment::fromMethodName(__METHOD__));
            } else {
                $existingAccount = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($accountIdentifier, $this->name);
                if ($existingAccount instanceof Account) {
                    foreach ($existingAccount->getRoles() as $role) {
                        $roleIdentifiers[] = $role->getIdentifier();
                    }
                    $this->logger?->debug(sprintf('OpenID Connect: Added roles (identity token %s) from existing account %s', $subject, self::describeValue($existingAccount->getAccountIdentifier())), LogEnvironment::fromMethodName(__METHOD__));
                } else {
                    $this->logger?->notice(sprintf('OpenID Connect: Could not add roles from existing account for identity token (%s) because the account %s (provider: %s) does not exist.', $subject, self::describeValue($accountIdentifier), $this->name), LogEnvironment::fromMethodName(__METHOD__));
                }
            }
        }

        return array_unique($roleIdentifiers);
    }

    /**
     * Returns a value taken from a token in a form which is safe to write into a log message
     */
    private static function describeValue(mixed $value): string
    {
        $description = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
        return mb_substr($description === false ? '?' : $description, 0, 200);
    }
}
