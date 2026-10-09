<?php
declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Authentication;

use DateTimeImmutable;
use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\CookieSettings;
use Flownative\OpenIdConnect\Client\ExpiredIdentityTokenException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\IdentityTokenRejectedException;
use Flownative\OpenIdConnect\Client\IdentityTokenRequirements;
use Flownative\OpenIdConnect\Client\IdentityTokenValidator;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClientFactory;
use Flownative\OpenIdConnect\Client\ServiceException;
use Flownative\OpenIdConnect\Client\TokenSet;
use Flownative\OpenIdConnect\Client\ValidatedIdentityToken;
use InvalidArgumentException;
use Neos\Cache\Exception as CacheException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Configuration\Exception\InvalidConfigurationTypeException;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Context as SecurityContext;
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
 *
 * With an OpenIdConnectToken, the provider authenticates a transient account on every request.
 * With an OpenIdConnectSessionToken, it signs in once to the persisted account which the
 * configured account resolver returns, and the Flow session keeps the login.
 */
final class OpenIdConnectProvider extends AbstractProvider
{
    /**
     * Seconds which compensate for clock differences between the identity provider and this application
     */
    private const int DEFAULT_LEEWAY = 60;

    private const string REFRESH_TOKEN_SESSION_KEY_PREFIX = 'flownative_oidc_refresh:';

    /**
     * How often a refreshed identity token is stored at most, if parallel requests keep replacing it in the session right after it was stored
     */
    private const int MAXIMUM_STORE_ATTEMPTS = 3;

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

    #[Flow\Inject]
    protected IdentityTokenValidator $identityTokenValidator;

    #[Flow\Inject]
    protected ObjectManagerInterface $objectManager;

    #[Flow\Inject]
    protected PersistenceManagerInterface $persistenceManager;

    #[Flow\Inject]
    protected SecurityContext $securityContext;

    #[Flow\Inject]
    protected IdentityTokenOfLogin $identityTokenOfLogin;

    #[Flow\InjectConfiguration(path: 'middleware')]
    protected array $middlewareSettings = [];

    public function getTokenClassNames(): array
    {
        return [OpenIdConnectToken::class, OpenIdConnectSessionToken::class];
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
        if (!$authenticationToken instanceof OpenIdConnectToken && !$authenticationToken instanceof OpenIdConnectSessionToken) {
            throw new UnsupportedAuthenticationTokenException(sprintf('The OpenID Connect authentication provider cannot authenticate the given token of type %s.', get_class($authenticationToken)), 1559805996);
        }
        if ($authenticationToken instanceof OpenIdConnectSessionToken) {
            $this->validateSessionModeOptions();
        } elseif (!isset($this->options['roles']) && !isset($this->options['rolesFromClaims']) && !isset($this->options['addRolesFromExistingAccount'])) {
            throw new RuntimeException('Either "roles", "rolesFromClaims" or "addRolesFromExistingAccount" must be specified in the configuration of OpenID Connect authentication provider', 1559806095);
        }
        if (!isset($this->options['serviceName'])) {
            throw new RuntimeException('Missing "serviceName" option in the configuration of OpenID Connect authentication provider', 1561480057);
        }
        if (!isset($this->options['accountIdentifierTokenValueName'])) {
            $this->options['accountIdentifierTokenValueName'] = 'sub';
        }
        $leeway = $this->options['leeway'] ?? self::DEFAULT_LEEWAY;
        if (!is_int($leeway) || $leeway < 0) {
            throw new RuntimeException('The "leeway" option in the configuration of OpenID Connect authentication provider must be zero or a positive number of seconds', 1789122177);
        }
        $this->options['requireVerifiedEmail'] ??= true;
        if (!is_bool($this->options['requireVerifiedEmail'])) {
            throw new RuntimeException('The "requireVerifiedEmail" option in the configuration of OpenID Connect authentication provider must be a boolean', 1789126720);
        }

        if ($authenticationToken instanceof OpenIdConnectSessionToken) {
            $this->authenticateSessionToken($authenticationToken, $leeway);
            return;
        }

        try {
            $identityToken = $authenticationToken->extractIdentityTokenFromRequest(CookieSettings::fromMiddlewareSettings($this->middlewareSettings)->getJwtCookieName($this->options));
        } catch (AuthenticationRequiredException) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            return;
        } catch (SecurityException $exception) {
            $this->logger?->notice(sprintf('OpenID Connect: Could not extract an identity token from the request: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        $client = $this->createClient();
        if ($client === null) {
            return;
        }

        $requirements = $this->createIdentityTokenRequirements($client->getOptions(), $leeway);
        $now = new DateTimeImmutable();
        try {
            $validatedIdentityToken = $this->identityTokenValidator->validate($identityToken, $client, $requirements, $now);
        } catch (ExpiredIdentityTokenException) {
            // All other checks passed, so the token may still be refreshed
            $validatedIdentityToken = null;
        } catch (IdentityTokenRejectedException $exception) {
            $this->logRejectedIdentityToken($exception);
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        } catch (ConnectionException|ServiceException $exception) {
            $this->logUnavailableJwks($exception);
            return;
        }

        if ($authenticationToken->hasFinishedAuthorization()) {
            $this->renewSessionAfterLogin($identityToken, $authenticationToken->getRefreshToken());
        }

        // Clients which send a bearer token must refresh it themselves, because they never receive a token refreshed here
        if ($validatedIdentityToken === null && !$authenticationToken->hasBearerAuthorizationHeader()) {
            $storedRefreshToken = $this->findStoredRefreshToken($identityToken);
            $refreshedTokenSet = $storedRefreshToken !== null ? $this->refreshExpiredIdentityToken($identityToken, $storedRefreshToken, $client, $now) : null;
            if ($refreshedTokenSet !== null) {
                try {
                    $validatedRefreshedIdentityToken = $this->identityTokenValidator->validate($refreshedTokenSet->identityToken, $client, $requirements, $now);
                } catch (ExpiredIdentityTokenException) {
                    $validatedRefreshedIdentityToken = null;
                } catch (IdentityTokenRejectedException $exception) {
                    $this->logRejectedIdentityToken($exception);
                    $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                    return;
                } catch (ConnectionException|ServiceException $exception) {
                    $this->logUnavailableJwks($exception);
                    return;
                }
                if (!$this->isRefreshOf($refreshedTokenSet->identityToken, $identityToken)) {
                    $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                    return;
                }
                if ($validatedRefreshedIdentityToken !== null && $this->storeRefreshedIdentityToken($identityToken, $refreshedTokenSet, $now->getTimestamp())) {
                    $validatedIdentityToken = $validatedRefreshedIdentityToken;
                }
            }
        }

        if ($validatedIdentityToken === null) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            $this->logger?->info(sprintf('OpenID Connect: The identity token %s is expired, need to re-authenticate', self::describeValue($identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null)), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }
        $identityToken = $validatedIdentityToken->identityToken;

        $roleIdentifiers = $this->getConfiguredRoles($identityToken);

        $account = $this->createTransientAccount($validatedIdentityToken->accountIdentifier, $roleIdentifiers, $identityToken->asJwt());
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

    /**
     * Signs in to the account which the account resolver returns for the identity token of a finished authorization
     *
     * Flow tags the session with the account, because the token is not sessionless, and renews the session identifier after the login:
     * Neos\Flow\Package connects a slot to the signal "authenticatedToken" of the AuthenticationProviderManager for that.
     *
     * @throws InvalidAuthenticationStatusException
     */
    private function authenticateSessionToken(OpenIdConnectSessionToken $authenticationToken, int $leeway): void
    {
        try {
            $identityToken = $authenticationToken->extractIdentityTokenFromRequest();
        } catch (AuthenticationRequiredException) {
            return;
        } catch (SecurityException $exception) {
            $this->logger?->notice(sprintf('OpenID Connect: Could not extract an identity token from the request: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        $client = $this->createClient();
        if ($client === null) {
            return;
        }

        // An expired token can't be refreshed here, because the session decides how long the login lasts
        try {
            $validatedIdentityToken = $this->identityTokenValidator->validate($identityToken, $client, $this->createIdentityTokenRequirements($client->getOptions(), $leeway));
        } catch (IdentityTokenRejectedException $exception) {
            $this->logRejectedIdentityToken($exception);
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        } catch (ConnectionException|ServiceException $exception) {
            $this->logUnavailableJwks($exception);
            return;
        }

        if ($authenticationToken->hasReceivedRefreshToken()) {
            $this->logger?->warning(sprintf('OpenID Connect: The identity provider of service "%s" issued a refresh token, which the session mode discards. Set the entry point option "requestRefreshToken" to false.', $this->options['serviceName']), LogEnvironment::fromMethodName(__METHOD__));
        }

        $account = $this->resolveAccount($validatedIdentityToken);
        if ($account === null) {
            $this->logger?->notice(sprintf('OpenID Connect: No account was admitted for the identity %s of service "%s"', self::describeValue($validatedIdentityToken->accountIdentifier), $this->options['serviceName']), LogEnvironment::fromMethodName(__METHOD__));
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        // The browser returns from the identity provider with a GET request, in which Flow only persists objects which are allowed
        if (!$this->persistenceManager->isNewObject($account)) {
            $this->accountRepository->update($account);
            $this->persistenceManager->allowObject($account);
        }
        // A refresh token which a login in the JWT mode left in the session must not outlive the switch to the session mode
        if ($this->session->isStarted()) {
            $this->session->putData($this->getRefreshTokenSessionKey(), null);
        }
        // The identity provider expects the identity token as a hint when the user signs out
        $this->identityTokenOfLogin->rememberInSession($this->name, $validatedIdentityToken->identityToken);
        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->logger?->debug(sprintf('OpenID Connect: Successfully authenticated persisted account %s with authentication provider %s', self::describeValue($account->getAccountIdentifier()), $this->name), LogEnvironment::fromMethodName(__METHOD__));

        $this->emitAuthenticated($authenticationToken, $validatedIdentityToken->identityToken, $this->policyService->getRoles());
    }

    /**
     * Roles of a persisted account belong to the account, so options which add roles would change the account itself
     */
    private function validateSessionModeOptions(): void
    {
        foreach (['roles', 'rolesFromClaims', 'addRolesFromExistingAccount'] as $optionName) {
            if (isset($this->options[$optionName])) {
                throw new RuntimeException(sprintf('The "%s" option of the OpenID Connect authentication provider cannot be used with the %s, because the roles of a persisted account belong to the account', $optionName, OpenIdConnectSessionToken::class), 1791540872);
            }
        }
        $accountResolverObjectName = $this->options['accountResolver'] ?? null;
        if (!is_string($accountResolverObjectName) || $accountResolverObjectName === '') {
            throw new RuntimeException(sprintf('The "accountResolver" option of the OpenID Connect authentication provider must name an implementation of %s, if it authenticates the %s', AccountResolverInterface::class, OpenIdConnectSessionToken::class), 1791540873);
        }
        if (isset($this->options['lookupProviderName']) && (!is_string($this->options['lookupProviderName']) || $this->options['lookupProviderName'] === '')) {
            throw new RuntimeException('The "lookupProviderName" option of the OpenID Connect authentication provider must be the name of an authentication provider', 1791540874);
        }
    }

    private function resolveAccount(ValidatedIdentityToken $validatedIdentityToken): ?Account
    {
        $accountResolver = $this->objectManager->get($this->options['accountResolver']);
        if (!$accountResolver instanceof AccountResolverInterface) {
            throw new RuntimeException(sprintf('The account resolver %s of the OpenID Connect authentication provider does not implement %s', $this->options['accountResolver'], AccountResolverInterface::class), 1791540875);
        }
        $lookupProviderName = $this->options['lookupProviderName'] ?? $this->name;
        // Policies may restrict access to accounts, but the account of somebody who is about to sign in must be found
        return $this->securityContext->withoutAuthorizationChecks(static fn (): ?Account => $accountResolver->resolve($validatedIdentityToken, $lookupProviderName));
    }

    /**
     * Creating the client may already contact the identity provider for discovery
     */
    private function createClient(): ?OpenIdConnectClient
    {
        try {
            return $this->openIdConnectClientFactory->create($this->options['serviceName']);
        } catch (ConnectionException|ServiceException $exception) {
            $this->logger?->error(sprintf('OpenID Connect: Could not retrieve the configuration of service "%s": %s', $this->options['serviceName'], $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return null;
        }
    }

    /**
     * Gives the session a new identifier after a login, and stores the refresh token of the login in it
     *
     * A session which existed before the login may be known to somebody else, for example through a session cookie planted in the
     * browser. With the old identifier, that person could use the refresh token of this login.
     */
    private function renewSessionAfterLogin(IdentityToken $identityToken, string $refreshToken): void
    {
        if ($this->session->canBeResumed()) {
            $this->session->resume();
        }
        if ($this->session->isStarted()) {
            $this->session->renewId();
        } elseif ($refreshToken !== '') {
            $this->session->start();
        }

        if ($refreshToken !== '') {
            $this->storeRefreshToken(StoredRefreshToken::forLogin($refreshToken, $identityToken));
        } elseif ($this->session->isStarted()) {
            // The refresh token of an earlier login in this browser must not outlive the new login
            $this->session->putData($this->getRefreshTokenSessionKey(), null);
        }
    }

    /**
     * Each authentication provider keeps its own refresh token, so that a login with one provider doesn't replace the token of another
     */
    private function getRefreshTokenSessionKey(): string
    {
        return self::REFRESH_TOKEN_SESSION_KEY_PREFIX . $this->name;
    }

    private function storeRefreshToken(StoredRefreshToken $storedRefreshToken): void
    {
        if (!$this->session->isStarted()) {
            $this->logger?->debug('OpenID Connect: Could not store refresh token in session', LogEnvironment::fromMethodName(__METHOD__));
            return;
        }
        $this->session->putData($this->getRefreshTokenSessionKey(), $storedRefreshToken->toSessionData());
        $this->logger?->debug('OpenID Connect: Stored refresh token in session', LogEnvironment::fromMethodName(__METHOD__));
    }

    private function findStoredRefreshToken(IdentityToken $identityToken): ?StoredRefreshToken
    {
        // Only an existing session can hold a refresh token, so no session is started here
        if ($this->session->canBeResumed()) {
            $this->session->resume();
        }
        $storedRefreshToken = $this->readStoredRefreshToken();
        if ($storedRefreshToken === null) {
            $this->logger?->info(sprintf('OpenID Connect: The identity token %s is expired, no refresh token in session', self::describeValue($identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null)), LogEnvironment::fromMethodName(__METHOD__));
        }
        return $storedRefreshToken;
    }

    /**
     * Reads the refresh token from the session storage
     *
     * Flow reads session data from the storage on each call, so the result contains what parallel requests stored meanwhile.
     */
    private function readStoredRefreshToken(): ?StoredRefreshToken
    {
        return $this->session->isStarted() ? StoredRefreshToken::fromSessionData($this->session->getData($this->getRefreshTokenSessionKey())) : null;
    }

    /**
     * Returns a new identity token for the expired one, or null if it cannot be refreshed
     *
     * Only identity tokens of the current generation are refreshed at the identity provider. A request which still carries an identity
     * token of the previous generation receives the refreshed identity token from the session, if the refresh happened a short while ago.
     */
    private function refreshExpiredIdentityToken(IdentityToken $identityToken, StoredRefreshToken $storedRefreshToken, OpenIdConnectClient $client, DateTimeImmutable $now): ?TokenSet
    {
        $accountIdentifier = self::describeValue($identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null);

        if ($storedRefreshToken->hasRecentlyReplaced($identityToken, $now->getTimestamp())) {
            $this->logger?->debug(sprintf('OpenID Connect: The identity token %s was refreshed a short while ago, using the refreshed identity token from the session', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
            try {
                return new TokenSet(IdentityToken::fromJwt($storedRefreshToken->identityToken), '');
            } catch (InvalidArgumentException) {
                return null;
            }
        }
        if (!$storedRefreshToken->isBoundTo($identityToken)) {
            $this->logger?->notice(sprintf('OpenID Connect: The identity token %s is expired, but the refresh token in the session belongs to another identity token', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
            return null;
        }

        $this->logger?->info(sprintf('OpenID Connect: The identity token %s is expired, trying to refresh it with the refresh token from the session', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
        try {
            return $client->refreshIdentityToken($storedRefreshToken->refreshToken);
        } catch (ConnectionException|ServiceException $exception) {
            $this->logger?->info(sprintf('OpenID Connect: Could not refresh the identity token: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return null;
        }
    }

    /**
     * Stores the refreshed identity token in the session, together with the identity tokens which parallel requests stored meanwhile
     *
     * The session data is read again right before each write, because parallel requests may have refreshed the same generation while
     * this request waited for the identity provider. Session data is written without a lock, so each write is confirmed by reading it
     * once more. An identity token which this request received from the session is already stored. Returns false if the session doesn't
     * accept the expired identity token anymore, for example after a logout.
     */
    private function storeRefreshedIdentityToken(IdentityToken $expiredIdentityToken, TokenSet $refreshedTokenSet, int $now): bool
    {
        $accountIdentifier = self::describeValue($expiredIdentityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null);
        for ($attempt = 1; $attempt <= self::MAXIMUM_STORE_ATTEMPTS; $attempt++) {
            $storedRefreshToken = $this->readStoredRefreshToken();
            if ($storedRefreshToken?->isBoundTo($refreshedTokenSet->identityToken)) {
                return true;
            }

            if ($storedRefreshToken?->isBoundTo($expiredIdentityToken)) {
                $this->storeRefreshToken($storedRefreshToken->withRefreshedIdentityToken($refreshedTokenSet->identityToken, $refreshedTokenSet->refreshToken, $now));
            } elseif ($storedRefreshToken?->hasRecentlyReplaced($expiredIdentityToken, $now)) {
                $this->logger?->debug(sprintf('OpenID Connect: A parallel request refreshed the identity token %s as well, adding the refreshed identity token to the session', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
                $this->storeRefreshToken($storedRefreshToken->withIdentityTokenOfParallelRefresh($refreshedTokenSet->identityToken, $refreshedTokenSet->refreshToken));
            } else {
                $this->logger?->notice(sprintf('OpenID Connect: Discarded the refreshed identity token %s, because the session no longer holds the refresh token of the expired identity token', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
                return false;
            }
        }

        if (!$this->readStoredRefreshToken()?->isBoundTo($refreshedTokenSet->identityToken)) {
            $this->logger?->warning(sprintf('OpenID Connect: Could not store the refreshed identity token %s in the session, because parallel requests kept replacing it', $accountIdentifier), LogEnvironment::fromMethodName(__METHOD__));
        }
        return true;
    }

    /**
     * A refreshed identity token must have the same issuer and subject as the expired one
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
     */
    private function isRefreshOf(IdentityToken $refreshedIdentityToken, IdentityToken $expiredIdentityToken): bool
    {
        if (self::hasIssuerAndSubject($refreshedIdentityToken, $expiredIdentityToken->values['iss'] ?? null, $expiredIdentityToken->values['sub'] ?? null)) {
            return true;
        }
        $this->logger?->notice(sprintf('OpenID Connect: Rejected the refreshed identity token for service "%s", because its issuer or subject differs from the expired identity token', $this->options['serviceName']), LogEnvironment::fromMethodName(__METHOD__));
        return false;
    }

    private static function hasIssuerAndSubject(IdentityToken $identityToken, mixed $issuer, mixed $subject): bool
    {
        return is_string($issuer) && is_string($subject) && ($identityToken->values['iss'] ?? null) === $issuer && ($identityToken->values['sub'] ?? null) === $subject;
    }

    /**
     * The "issuer" and "audience" options of the provider take precedence over the issuer and the client id of the service
     *
     * The authorized party ("azp") is checked against the client id for every token addressed to this client, also with an "audience"
     * option. Access tokens for an API, which other clients obtained, are left alone, because their audience doesn't contain it.
     */
    private function createIdentityTokenRequirements(array $clientOptions, int $leeway): IdentityTokenRequirements
    {
        $issuers = self::toListOfNonEmptyStrings($this->options['issuer'] ?? $clientOptions['issuer'] ?? []);
        if ($issuers === []) {
            throw new RuntimeException(sprintf('OpenID Connect: The issuer of service "%s" is unknown. Configure the "issuer" option of the authentication provider or the service, or a "discoveryUri" for the service', $this->options['serviceName']), 1789122175);
        }
        $audiences = self::toListOfNonEmptyStrings($this->options['audience'] ?? $clientOptions['clientId'] ?? []);
        if ($audiences === []) {
            throw new RuntimeException(sprintf('OpenID Connect: No audience is configured for the authentication provider of service "%s". Configure the "audience" option or the "clientId" of the service', $this->options['serviceName']), 1789122176);
        }
        $clientId = $clientOptions['clientId'] ?? null;
        $authorizedParty = is_string($clientId) && $clientId !== '' ? $clientId : null;

        return new IdentityTokenRequirements(
            issuers: $issuers,
            audiences: $audiences,
            authorizedParty: $authorizedParty,
            accountIdentifierClaimName: $this->options['accountIdentifierTokenValueName'],
            requireVerifiedEmail: $this->options['requireVerifiedEmail'],
            leeway: $leeway,
        );
    }

    /**
     * @return string[]
     */
    private static function toListOfNonEmptyStrings(mixed $value): array
    {
        if (is_string($value)) {
            $value = [$value];
        }
        if (!is_array($value)) {
            return [];
        }
        return array_values(array_filter($value, static fn (mixed $item): bool => is_string($item) && $item !== ''));
    }

    /**
     * An identity provider which can't be reached proves nothing about the token, so the token doesn't count as wrong credentials
     */
    private function logUnavailableJwks(ConnectionException|ServiceException $exception): void
    {
        $this->logger?->error(sprintf('OpenID Connect: Could not retrieve the JSON Web Key Set of service "%s": %s', $this->options['serviceName'], $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
    }

    private function logRejectedIdentityToken(IdentityTokenRejectedException $exception): void
    {
        $this->logger?->notice(sprintf('OpenID Connect: Rejected the identity token for service "%s", because %s', $this->options['serviceName'], $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
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
                if (!$existingAccount instanceof Account) {
                    $this->logger?->notice(sprintf('OpenID Connect: Could not add roles from existing account for identity token (%s) because the account %s (provider: %s) does not exist.', $subject, self::describeValue($accountIdentifier), $this->name), LogEnvironment::fromMethodName(__METHOD__));
                } elseif (strcasecmp($existingAccount->getAccountIdentifier(), $accountIdentifier) !== 0) {
                    // Depending on its collation, the database also finds identifiers which only look similar, for example with accents or trailing spaces.
                    $this->logger?->notice(sprintf('OpenID Connect: Did not add roles of existing account %s for identity token (%s), because its account identifier differs from %s', self::describeValue($existingAccount->getAccountIdentifier()), $subject, self::describeValue($accountIdentifier)), LogEnvironment::fromMethodName(__METHOD__));
                } else {
                    foreach ($existingAccount->getRoles() as $role) {
                        $roleIdentifiers[] = $role->getIdentifier();
                    }
                    $this->logger?->debug(sprintf('OpenID Connect: Added roles (identity token %s) from existing account %s', $subject, self::describeValue($existingAccount->getAccountIdentifier())), LogEnvironment::fromMethodName(__METHOD__));
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
